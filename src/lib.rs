mod common;
mod config;
mod proxy;
mod stats_do;

use crate::config::{Config, ProxyMode};
use crate::proxy::*;

use std::collections::HashMap;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde_json::json;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+-\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());
static SOCKS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^socks5?=(?:([^:@/]+):([^@/]+)@)?([^@/]+)-(\d+)$").unwrap()
});
static HTTP_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^http=(?:([^:@/]+):([^@/]+)@)?([^@/]+)-(\d+)$").unwrap()
});

struct AppState {
    ctx: Context,
    config: Config,
}

#[event(fetch)]
async fn main(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let main_page_url = env.var("MAIN_PAGE_URL").map(|x|x.to_string())?;
    let sub_page_url = env.var("SUB_PAGE_URL").map(|x|x.to_string())?;
    let kv = env.kv("SIREN")?;
    let stats_stub = env.durable_object("STATS")?.id_from_name("global")?.get_stub()?;
    let config = Config { uuid, host: host.clone(), proxy_addr: host, proxy_port: 443, proxy_mode: ProxyMode::Direct, kv, stats: stats_stub, main_page_url, sub_page_url };
    let state = AppState { ctx, config };

    Router::with_data(state)
        .on_async("/", fe)
        .on_async("/sub", sub)
        .on("/link", link)
        .on_async("/api/stats", stats)
        .on_async("/:proxyip", tunnel)
        .run(req, env)
        .await
}

async fn get_response_from_url(url: String) -> Result<Response> {
    let req = Fetch::Url(Url::parse(url.as_str())?);
    let mut res = req.send().await?;
    Response::from_html(res.text().await?)
}

async fn fe(_: Request, cx: RouteContext<AppState>) -> Result<Response> {
    get_response_from_url(cx.data.config.main_page_url).await
}

async fn sub(_: Request, cx: RouteContext<AppState>) -> Result<Response> {
    get_response_from_url(cx.data.config.sub_page_url).await
}

async fn stats(_: Request, cx: RouteContext<AppState>) -> Result<Response> {
    cx.data.config.stats.fetch_with_str("https://stats.internal/stats").await
}


async fn tunnel(req: Request, mut cx: RouteContext<AppState>) -> Result<Response> {
    let mut proxyip = cx.param("proxyip").unwrap().to_string();

    if let Some(caps) = SOCKS_PATTERN.captures(&proxyip) {
        let user = caps.get(1).map(|m| m.as_str().to_string());
        let pass = caps.get(2).map(|m| m.as_str().to_string());
        let host = caps[3].to_string();
        if let Ok(port) = caps[4].parse::<u16>() {
            cx.data.config.proxy_mode = ProxyMode::Socks5 { host, port, user, pass };
        }
    } else if let Some(caps) = HTTP_PATTERN.captures(&proxyip) {
        let user = caps.get(1).map(|m| m.as_str().to_string());
        let pass = caps.get(2).map(|m| m.as_str().to_string());
        let host = caps[3].to_string();
        if let Ok(port) = caps[4].parse::<u16>() {
            cx.data.config.proxy_mode = ProxyMode::Http { host, port, user, pass };
        }
    } else if PROXYKV_PATTERN.is_match(&proxyip)  {
        let kvid_list: Vec<String> = proxyip.split(",").map(|s|s.to_string()).collect();
        let mut proxy_kv_str = cx.data.config.kv.get("proxy_kv").text().await?.unwrap_or("".to_string());
        let mut rand_buf = [0u8, 1];
        getrandom::getrandom(&mut rand_buf).expect("failed generating random number");
        
        if proxy_kv_str.len() == 0 {
            console_log!("getting proxy kv from github...");
            let req = Fetch::Url(Url::parse("https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json")?);
            let mut res = req.send().await?;
            if res.status_code() == 200 {
                proxy_kv_str = res.text().await?.to_string();
                cx.data.config.kv.put("proxy_kv", &proxy_kv_str)?.expiration_ttl(60 * 60 * 24).execute().await?;
            } else {
                return Err(Error::from(format!("error getting proxy kv: {}", res.status_code())));
            }
        }
        
        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str)?;
        
        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        proxyip = kvid_list[kv_index].clone();
        
        let proxyip_index = (rand_buf[0] as usize) % proxy_kv[&proxyip].len();
        proxyip = proxy_kv[&proxyip][proxyip_index].clone().replace(":", "-");
    }

    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade == "websocket".to_string() && PROXYIP_PATTERN.is_match(&proxyip) {
        if matches!(cx.data.config.proxy_mode, ProxyMode::Direct) {
            if let Some((addr, port_str)) = proxyip.split_once('-') {
                if let Ok(port) = port_str.parse() {
                    cx.data.config.proxy_addr = addr.to_string();
                    cx.data.config.proxy_port = port;
                }
            }
        }
        
        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;

        let AppState { ctx, config } = cx.data;
        ctx.wait_until(async move {
            let events = server.events().unwrap();
            if let Err(e) = ProxyStream::new(config, &server, events).process().await {
                console_error!("[tunnel]: {}", e);
            }
        });
    
        Response::from_websocket(client)
    } else {
        Response::from_html("hi from wasm!")
    }

}

fn link(_: Request, cx: RouteContext<AppState>) -> Result<Response> {
    let host = cx.data.config.host.to_string();
    let uuid = cx.data.config.uuid.to_string();

    let vmess_link = {
        let config = json!({
            "ps": "siren vmess",
            "v": "2",
            "add": host,
            "port": "443",
            "id": uuid,
            "aid": "0",
            "scy": "zero",
            "net": "ws",
            "type": "none",
            "host": host,
            "path": "/SG",
            "tls": "tls",
            "sni": host,
            "alpn": ""}
        );
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };
    let vless_link = format!("vless://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FSG&security=tls&sni={host}#siren vless");
    let trojan_link = format!("trojan://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2FSG&security=tls&sni={host}#siren trojan");
    let ss_link = format!("ss://{}@{host}:443?plugin=v2ray-plugin%3Btls%3Bmux%3D0%3Bmode%3Dwebsocket%3Bpath%3D%2FSG%3Bhost%3D{host}#siren ss", URL_SAFE.encode(format!("none:{uuid}")));
    
    Response::from_body(ResponseBody::Body(format!("{vmess_link}\n{vless_link}\n{trojan_link}\n{ss_link}").into()))
}
