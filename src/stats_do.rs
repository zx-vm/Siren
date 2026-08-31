use std::cell::RefCell;
use serde_json::json;
use worker::*;

#[derive(Clone, Copy, Default)]
struct Counters {
    up_bytes: u64,
    down_bytes: u64,
    connections: u64,
    first_seen: u64,
}

#[durable_object]
pub struct StatsCounter {
    state: State,
    cache: RefCell<Option<Counters>>,
}

impl DurableObject for StatsCounter {
    fn new(state: State, _env: Env) -> Self {
        Self { state, cache: RefCell::new(None) }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path().to_string();

        if path == "/record" {
            let mut up: u64 = 0;
            let mut down: u64 = 0;
            for (k, v) in url.query_pairs() {
                match k.as_ref() {
                    "up" => up = v.parse().unwrap_or(0),
                    "down" => down = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
            self.handle_record(up, down).await
        } else {
            self.handle_stats().await
        }
    }
}

impl StatsCounter {
    async fn load(&self) -> Result<Counters> {
        if let Some(c) = *self.cache.borrow() {
            return Ok(c);
        }

        let up_bytes: u64 = self.state.storage().get("up_bytes").await.unwrap_or(0);
        let down_bytes: u64 = self.state.storage().get("down_bytes").await.unwrap_or(0);
        let connections: u64 = self.state.storage().get("connections").await.unwrap_or(0);
        let first_seen: u64 = match self.state.storage().get::<u64>("first_seen").await {
            Ok(ts) => ts,
            Err(_) => {
                let now = Date::now().as_millis();
                self.state.storage().put("first_seen", now).await?;
                now
            }
        };

        let c = Counters { up_bytes, down_bytes, connections, first_seen };
        *self.cache.borrow_mut() = Some(c);
        Ok(c)
    }

    async fn handle_record(&self, up: u64, down: u64) -> Result<Response> {
        let mut c = self.load().await?;
        c.up_bytes += up;
        c.down_bytes += down;
        c.connections += 1;
        *self.cache.borrow_mut() = Some(c);

        self.state.storage().put("up_bytes", c.up_bytes).await?;
        self.state.storage().put("down_bytes", c.down_bytes).await?;
        self.state.storage().put("connections", c.connections).await?;

        Response::ok("ok")
    }

    async fn handle_stats(&self) -> Result<Response> {
        let c = self.load().await?;
        let now = Date::now().as_millis();
        let uptime_seconds = now.saturating_sub(c.first_seen) / 1000;

        Response::from_json(&json!({
            "up_bytes": c.up_bytes,
            "down_bytes": c.down_bytes,
            "total_bytes": c.up_bytes + c.down_bytes,
            "connections": c.connections,
            "first_seen": c.first_seen,
            "uptime_seconds": uptime_seconds,
        }))
    }
}
