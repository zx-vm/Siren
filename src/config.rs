use uuid::Uuid;
use worker::kv::KvStore;
use worker::Stub;

#[derive(Clone)]
pub enum ProxyMode {
    Direct,
    Socks5 {
        host: String,
        port: u16,
        user: Option<String>,
        pass: Option<String>,
    },
    Http {
        host: String,
        port: u16,
        user: Option<String>,
        pass: Option<String>,
    },
}

pub struct Config {
    pub uuid: Uuid,
    pub host: String,
    pub proxy_addr: String,
    pub proxy_port: u16,
    pub proxy_mode: ProxyMode,
    pub kv: KvStore,
    pub stats: Stub,

    pub main_page_url: String,
    pub sub_page_url: String,
}
