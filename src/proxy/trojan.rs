use super::ProxyStream;
use tokio::io::AsyncReadExt;
use crate::common::{parse_addr, parse_port, AddrKind};
use sha2::{Digest, Sha224};
use worker::*;

impl <'a> ProxyStream<'a> {
    pub async fn process_trojan(&mut self) -> Result<()> {
        let mut user_id = [0u8; 56];
        self.read_exact(&mut user_id).await?;

        let expected_hash = Sha224::digest(self.config.uuid.to_string().as_bytes());
        let expected_hex: String = expected_hash.iter().map(|b| format!("{:02x}", b)).collect();
        if user_id.as_slice() != expected_hex.as_bytes() {
            return Err(Error::RustError("invalid password".to_string()));
        }

        self.read_u16().await?;
        
        let network_type = self.read_u8().await?;
        let is_tcp = network_type == 1;

        let remote_addr = parse_addr(self, AddrKind::Socks5Like).await?;
        let remote_port = parse_port(self).await?;

        self.read_u16().await?;

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