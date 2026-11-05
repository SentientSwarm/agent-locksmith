use crate::{Error, fixture::Fixture};
use serde_json::json;
#[derive(Clone)]
pub struct Wire {
    pub session: Option<String>,
    http: reqwest::Client,
    url: String,
    bearer: String,
}
impl Wire {
    pub async fn open(f: &Fixture, _index: usize) -> Result<Self, Error> {
        let mut w = Self {
            session: None,
            http: reqwest::Client::builder().no_proxy().build()?,
            url: f.url.clone(),
            bearer: f.bearer.clone(),
        };
        let r = w
            .request(reqwest::Method::POST)
            .json(&crate::native::init(0))
            .send()
            .await?;
        w.session = Some(r.headers()["mcp-session-id"].to_str()?.into());
        assert!(r.text().await?.contains("2025-11-25"));
        *f.gateway.sessions.id.lock().unwrap() = w.session.clone();
        let r = w
            .request(reqwest::Method::POST)
            .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .send()
            .await?;
        assert_eq!(r.status(), 202);
        Ok(w)
    }
    pub fn request(&self, method: reqwest::Method) -> reqwest::RequestBuilder {
        let r = self
            .http
            .request(method, &self.url)
            .header("authorization", &self.bearer)
            .header("accept", "application/json, text/event-stream");
        match &self.session {
            Some(s) => r
                .header("mcp-session-id", s)
                .header("mcp-protocol-version", "2025-11-25"),
            None => r,
        }
    }
    pub async fn list(&self, id: i64) -> Result<(), Error> {
        let r = self
            .request(reqwest::Method::POST)
            .json(&json!({"jsonrpc":"2.0","id":id,"method":"tools/list"}))
            .send()
            .await?;
        assert!(r.text().await?.contains("\"name\":\"read\""));
        Ok(())
    }
}
