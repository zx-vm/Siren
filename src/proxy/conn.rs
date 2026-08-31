use crate::config::{Config, ProxyMode};

use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::{BufMut, BytesMut};
use futures_util::future::{select, Either};
use futures_util::Stream;
use pin_project_lite::pin_project;
use pretty_bytes::converter::convert;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use worker::*;

const OUTBOUND_HANDSHAKE_TIMEOUT_SECS: u64 = 1;

async fn with_timeout<F, T>(secs: u64, fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    let boxed_fut = Box::pin(fut);
    let boxed_timeout = Box::pin(Delay::from(Duration::from_secs(secs)));

    match select(boxed_fut, boxed_timeout).await {
        Either::Left((res, _)) => res,
        Either::Right((_, _)) => Err(Error::RustError(format!("timeout setelah {secs} detik"))),
    }
}

static MAX_WEBSOCKET_SIZE: usize = 512 * 1024;
static MAX_BUFFER_SIZE: usize = 1024 * 1024; 

pin_project! {
    pub struct ProxyStream<'a> {
        pub config: Config,
        pub ws: &'a WebSocket,
        pub buffer: BytesMut,
        #[pin]
        pub events: EventStream<'a>,
    }
}

impl<'a> ProxyStream<'a> {
    pub fn new(config: Config, ws: &'a WebSocket, events: EventStream<'a>) -> Self {
        let buffer = BytesMut::with_capacity(8 * 1024);

        Self {
            config,
            ws,
            buffer,
            events,
        }
    }
    
    pub async fn fill_buffer_until(&mut self, n: usize) -> std::io::Result<()> {
        use futures_util::StreamExt;

        while self.buffer.len() < n {
            match self.events.next().await {
                Some(Ok(WebsocketEvent::Message(msg))) => {
                    if let Some(data) = msg.bytes() {
                        self.buffer.put_slice(&data);
                    }
                }
                Some(Ok(WebsocketEvent::Close(_))) => {
                    break;
                }
                Some(Err(e)) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                }
                None => {
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn peek_buffer(&self, n: usize) -> &[u8] {
        let len = self.buffer.len().min(n);
        &self.buffer[..len]
    }

    pub async fn process(&mut self) -> Result<()> {
        let peek_buffer_len = 62;
        self.fill_buffer_until(peek_buffer_len).await?;
        let peeked_buffer = self.peek_buffer(peek_buffer_len);

        if peeked_buffer.len() < (peek_buffer_len/2) {
            return Err(Error::RustError("not enough buffer".to_string()));
        }

        if self.is_vless(peeked_buffer) {
            console_log!("vless detected!");
            self.process_vless().await
        } else if self.is_shadowsocks(peeked_buffer) {
            console_log!("shadowsocks detected!");
            self.process_shadowsocks().await
        } else if self.is_trojan(peeked_buffer) {
            console_log!("trojan detected!");
            self.process_trojan().await
        } else if self.is_vmess(peeked_buffer) {
            console_log!("vmess detected!");
            self.process_vmess().await
        } else {
            Err(Error::RustError("protocol not implemented".to_string()))
        }
    }

    pub fn is_vless(&self, buffer: &[u8]) -> bool {
        buffer[0] == 0
    }

    fn is_shadowsocks(&self, buffer: &[u8]) -> bool {
        match buffer[0] {
            1 => { // IPv4
                if buffer.len() < 7 {
                    return false;
                }
                let remote_port = u16::from_be_bytes([buffer[5], buffer[6]]);
                remote_port != 0
            }
            3 => { // Domain
                if buffer.len() < 2 {
                    return false;
                }
                let domain_len = buffer[1] as usize;
                if buffer.len() < 2 + domain_len + 2 {
                    return false;
                }
                let remote_port = u16::from_be_bytes([
                    buffer[2 + domain_len],
                    buffer[2 + domain_len + 1],
                ]);
                remote_port != 0
            }
            4 => { // IPv6
                if buffer.len() < 19 {
                    return false;
                }
                let remote_port = u16::from_be_bytes([buffer[17], buffer[18]]);
                remote_port != 0
            }
            _ => false,
        }
    }

    fn is_trojan(&self, buffer: &[u8]) -> bool {
        buffer.len() > 57 && buffer[56] == 13 && buffer[57] == 10
    }

    fn is_vmess(&self, buffer: &[u8]) -> bool {
        buffer.len() > 0 // fallback
    }

    async fn connect_direct(addr: String, port: u16) -> Result<Socket> {
        let mut s = Socket::builder().connect(&addr, port).map_err(|e| {
            Error::RustError(e.to_string())
        })?;
        s.opened().await.map_err(|e| {
            Error::RustError(e.to_string())
        })?;
        Ok(s)
    }

    async fn resolve_fallback_socket(
        proxy_mode: ProxyMode,
        remote_addr: String,
        remote_port: u16,
        proxy_addr: String,
        proxy_port: u16,
    ) -> Result<Socket> {
        match proxy_mode {
            ProxyMode::Direct => Self::connect_direct(proxy_addr, proxy_port).await,
            ProxyMode::Socks5 { host, port, user, pass } => {
                Self::socks5_handshake(host, port, user, pass, remote_addr, remote_port).await
            }
            ProxyMode::Http { host, port, user, pass } => {
                Self::http_connect_handshake(host, port, user, pass, remote_addr, remote_port).await
            }
        }
    }

    pub async fn handle_outbound(&mut self, remote_addr: String, remote_port: u16) -> Result<()> {
        let direct_fut = with_timeout(
            OUTBOUND_HANDSHAKE_TIMEOUT_SECS,
            Self::connect_direct(remote_addr.clone(), remote_port),
        );
        let fallback_fut = with_timeout(
            OUTBOUND_HANDSHAKE_TIMEOUT_SECS,
            Self::resolve_fallback_socket(
                self.config.proxy_mode.clone(),
                remote_addr.clone(),
                remote_port,
                self.config.proxy_addr.clone(),
                self.config.proxy_port,
            ),
        );

        let mut remote_socket = match select(Box::pin(direct_fut), Box::pin(fallback_fut)).await {
            Either::Left((Ok(s), _)) => s,
            Either::Left((Err(e1), pending_fallback)) => {
                console_log!("[direct] gagal/timeout ({}), nunggu jalur fallback...", e1);
                match pending_fallback.await {
                    Ok(s) => s,
                    Err(e2) => {
                        console_error!("[fallback] juga gagal: {}", e2);
                        return Ok(());
                    }
                }
            }
            Either::Right((Ok(s), _)) => s,
            Either::Right((Err(e2), pending_direct)) => {
                console_log!("[fallback] gagal/timeout ({}), nunggu jalur direct...", e2);
                match pending_direct.await {
                    Ok(s) => s,
                    Err(e1) => {
                        console_error!("[direct] juga gagal: {}", e1);
                        return Ok(());
                    }
                }
            }
        };

        let (up, down) = tokio::io::copy_bidirectional_with_sizes(self, &mut remote_socket, MAX_WEBSOCKET_SIZE, MAX_WEBSOCKET_SIZE)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;
        console_log!("copied data {}:{}, up: {} and dl: {}", &remote_addr, remote_port, convert(up as f64), convert(down as f64));
        self.record_usage(up, down).await;

        Ok(())
    }

    async fn socks5_handshake(
        proxy_host: String,
        proxy_port: u16,
        user: Option<String>,
        pass: Option<String>,
        target_addr: String,
        target_port: u16,
    ) -> Result<Socket> {
        let mut remote_socket = Socket::builder().connect(&proxy_host, proxy_port).map_err(|e| {
            Error::RustError(e.to_string())
        })?;
        remote_socket.opened().await.map_err(|e| Error::RustError(e.to_string()))?;

        let creds = user.as_ref().zip(pass.as_ref());

        let methods: &[u8] = if creds.is_some() { &[0x00, 0x02] } else { &[0x00] };
        let mut greeting = vec![0x05u8, methods.len() as u8];
        greeting.extend_from_slice(methods);
        remote_socket.write_all(&greeting).await.map_err(|e| Error::RustError(e.to_string()))?;

        let mut method_resp = [0u8; 2];
        remote_socket.read_exact(&mut method_resp).await.map_err(|e| Error::RustError(e.to_string()))?;
        if method_resp[0] != 0x05 {
            return Err(Error::RustError("versi SOCKS5 tidak valid dari proxy".to_string()));
        }

        match method_resp[1] {
            0x00 => {} 
            0x02 => {
                let (u, p) = creds.ok_or_else(|| Error::RustError("proxy SOCKS5 minta autentikasi, tapi user/pass tidak diisi".to_string()))?;
                let mut auth = vec![0x01u8, u.len() as u8];
                auth.extend_from_slice(u.as_bytes());
                auth.push(p.len() as u8);
                auth.extend_from_slice(p.as_bytes());
                remote_socket.write_all(&auth).await.map_err(|e| Error::RustError(e.to_string()))?;

                let mut auth_resp = [0u8; 2];
                remote_socket.read_exact(&mut auth_resp).await.map_err(|e| Error::RustError(e.to_string()))?;
                if auth_resp[1] != 0x00 {
                    return Err(Error::RustError("autentikasi SOCKS5 gagal".to_string()));
                }
            }
            0xFF => return Err(Error::RustError("proxy SOCKS5 menolak semua metode auth".to_string())),
            other => return Err(Error::RustError(format!("metode auth SOCKS5 tidak didukung: {other}"))),
        }

        let mut req = vec![0x05u8, 0x01, 0x00];
        if let Ok(ip) = target_addr.parse::<Ipv4Addr>() {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = target_addr.parse::<Ipv6Addr>() {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        } else {
            let domain = target_addr.as_bytes();
            if domain.len() > 255 {
                return Err(Error::RustError("domain terlalu panjang untuk SOCKS5".to_string()));
            }
            req.push(0x03);
            req.push(domain.len() as u8);
            req.extend_from_slice(domain);
        }
        req.extend_from_slice(&target_port.to_be_bytes());
        remote_socket.write_all(&req).await.map_err(|e| Error::RustError(e.to_string()))?;

        let mut head = [0u8; 4];
        remote_socket.read_exact(&mut head).await.map_err(|e| Error::RustError(e.to_string()))?;
        if head[0] != 0x05 {
            return Err(Error::RustError("versi SOCKS5 tidak valid pada balasan".to_string()));
        }
        if head[1] != 0x00 {
            return Err(Error::RustError(format!("proxy SOCKS5 menolak koneksi, kode {}", head[1])));
        }
        match head[3] {
            0x01 => {
                let mut rest = [0u8; 4 + 2];
                remote_socket.read_exact(&mut rest).await.map_err(|e| Error::RustError(e.to_string()))?;
            }
            0x04 => {
                let mut rest = [0u8; 16 + 2];
                remote_socket.read_exact(&mut rest).await.map_err(|e| Error::RustError(e.to_string()))?;
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                remote_socket.read_exact(&mut len_buf).await.map_err(|e| Error::RustError(e.to_string()))?;
                let mut rest = vec![0u8; len_buf[0] as usize + 2];
                remote_socket.read_exact(&mut rest).await.map_err(|e| Error::RustError(e.to_string()))?;
            }
            other => return Err(Error::RustError(format!("tipe alamat SOCKS5 tidak dikenal pada balasan: {other}"))),
        }

        Ok(remote_socket)
    }

    async fn http_connect_handshake(
        proxy_host: String,
        proxy_port: u16,
        user: Option<String>,
        pass: Option<String>,
        target_addr: String,
        target_port: u16,
    ) -> Result<Socket> {
        let mut remote_socket = Socket::builder().connect(&proxy_host, proxy_port).map_err(|e| {
            Error::RustError(e.to_string())
        })?;
        remote_socket.opened().await.map_err(|e| Error::RustError(e.to_string()))?;

        let target = format!("{target_addr}:{target_port}");
        let mut connect_req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let (Some(u), Some(p)) = (user.as_ref(), pass.as_ref()) {
            let basic = STANDARD.encode(format!("{u}:{p}"));
            connect_req.push_str(&format!("Proxy-Authorization: Basic {basic}\r\n"));
        }
        connect_req.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
        remote_socket.write_all(connect_req.as_bytes()).await.map_err(|e| Error::RustError(e.to_string()))?;

        let mut resp_buf: Vec<u8> = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        loop {
            remote_socket.read_exact(&mut byte).await.map_err(|e| Error::RustError(e.to_string()))?;
            resp_buf.push(byte[0]);
            if resp_buf.len() >= 4 && &resp_buf[resp_buf.len() - 4..] == b"\r\n\r\n" {
                break;
            }
            if resp_buf.len() > 8192 {
                return Err(Error::RustError("header balasan HTTP proxy kepanjangan".to_string()));
            }
        }

        let resp_text = String::from_utf8_lossy(&resp_buf);
        let status_line = resp_text.lines().next().unwrap_or_default();
        let status_ok = status_line
            .split_whitespace()
            .nth(1)
            .map(|code| code.starts_with('2'))
            .unwrap_or(false);
        if !status_ok {
            return Err(Error::RustError(format!("HTTP proxy menolak CONNECT: {status_line}")));
        }

        Ok(remote_socket)
    }

    async fn record_usage(&self, up: u64, down: u64) {
        if let Err(e) = self.record_usage_inner(up, down).await {
            console_error!("gagal update statistik pemakaian: {}", e);
        }
    }

    async fn record_usage_inner(&self, up: u64, down: u64) -> Result<()> {
        let url = format!("https://stats.internal/record?up={up}&down={down}");
        let mut res = self.config.stats.fetch_with_str(&url).await?;
        if res.status_code() != 200 {
            let body = res.text().await.unwrap_or_default();
            return Err(Error::RustError(format!("DO /record balas status {}: {}", res.status_code(), body)));
        }
        console_log!("statistik terkirim ke DO: up={} down={}", up, down);
        Ok(())
    }

    pub async fn handle_udp_outbound(&mut self) -> Result<()> {
        let mut buff = vec![0u8; 65535];

        let n = self.read(&mut buff).await?;
        let data = &buff[..n];
        if crate::dns::doh(data).await.is_ok() {
            self.write(&data).await?;
        };
        Ok(())
    }
}

impl<'a> AsyncRead for ProxyStream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let mut this = self.project();

        loop {
            let size = std::cmp::min(this.buffer.len(), buf.remaining());
            if size > 0 {
                buf.put_slice(&this.buffer.split_to(size));
                return Poll::Ready(Ok(()));
            }

            match this.events.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                    if let Some(data) = msg.bytes() {
                        if data.len() > MAX_WEBSOCKET_SIZE {
                            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "websocket buffer too long")))
                        }
                        
                        if this.buffer.len() + data.len() > MAX_BUFFER_SIZE {
                            console_log!("buffer full, applying backpressure");
                            return Poll::Pending;
                        }
                        
                        this.buffer.put_slice(&data);
                    }
                }
                Poll::Pending => return Poll::Pending,
                _ => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<'a> AsyncWrite for ProxyStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        return Poll::Ready(
            self.ws
                .send_with_bytes(buf)
                .map(|_| buf.len())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        );
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        match self.ws.close(Some(1000), Some("shutdown".to_string())) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
}
