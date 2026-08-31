use super::ProxyStream;
use crate::common::{parse_addr, parse_port, AddrKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use worker::*;

impl <'a> ProxyStream<'a> {
    pub async fn process_vless(&mut self) -> Result<()> {
        self.read_u8().await?;
        
        let mut user_id = [0u8; 16];
        self.read_exact(&mut user_id).await?;
        let uuid = Uuid::from_bytes(user_id);
        if uuid != self.config.uuid {
            return Err(Error::RustError("invalid uuid".to_string()));
        }
        
        let m_len = self.read_u8().await?;
        let mut protobuf = vec![0u8; m_len as _];
        self.read_exact(&mut protobuf).await?;

        let network_type = self.read_u8().await?;
        let is_tcp = network_type == 1;

        let remote_port = parse_port(self).await?;
        let remote_addr = parse_addr(self, AddrKind::VlessVmess).await?;

        if is_tcp {
            self.write(&[0u8; 2]).await?;
            self.handle_outbound(remote_addr, remote_port).await?;
        } else {
            if let Err(e) = self.handle_udp_outbound().await {
                console_error!("error handling udp: {}", e)
            }
        }

        Ok(())
    }
}