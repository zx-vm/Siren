use super::ProxyStream;
use crate::common::{parse_addr, parse_port, AddrKind};
use worker::*;

impl <'a> ProxyStream<'a> {
    pub async fn process_shadowsocks(&mut self) -> Result<()> {
        let remote_addr = parse_addr(self, AddrKind::Socks5Like).await?;
        let remote_port = parse_port(self).await?;
        
        let is_tcp = true;
        
        if is_tcp {
            self.handle_outbound(remote_addr, remote_port).await?;
        } else {
            if let Err(e) = self.handle_udp_outbound().await {
                console_error!("error handling udp: {}", e)
            }
        }

        Ok(())
    }
}