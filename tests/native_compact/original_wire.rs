//! Compact wire-only adaptation. The original S3 assertions remain unchanged.
use crate::{Error, fixture::Fixture};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
#[derive(Clone)]
pub struct Wire {
    pub session: Option<String>,
    http: reqwest::Client,
    url: String,
    bearer: String,
    described: Arc<Mutex<Option<Value>>>,
}
pub struct Request {
    inner: reqwest::RequestBuilder,
    described: Arc<Mutex<Option<Value>>>,
}
impl Request {
    pub fn json(self, value: &Value) -> reqwest::RequestBuilder {
        let mut value = value.clone();
        if value["method"] == "tools/call" && value["params"]["name"] == "read" {
            let receipt = self.described.lock().unwrap();
            let receipt = receipt
                .as_ref()
                .expect("full describe before original call");
            value["params"] = json!({"name":"invoke","arguments":{"handle":receipt["handle"],"contract_digest":receipt["contract_digest"],"arguments":value["params"]["arguments"]}});
        }
        self.inner.json(&value)
    }
}
impl Wire {
    pub async fn open(f: &Fixture, _index: usize) -> Result<Self, Error> {
        let mut w = Self {
            session: None,
            http: reqwest::Client::builder().no_proxy().build()?,
            url: f.url.clone(),
            bearer: f.bearer.clone(),
            described: Default::default(),
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
    pub fn request(&self, method: reqwest::Method) -> Request {
        let mut r = self
            .http
            .request(method, &self.url)
            .header("authorization", &self.bearer)
            .header("accept", "application/json, text/event-stream");
        if let Some(s) = &self.session {
            r = r
                .header("mcp-session-id", s)
                .header("mcp-protocol-version", "2025-11-25");
        }
        Request {
            inner: r,
            described: self.described.clone(),
        }
    }
    pub async fn list(&self, id: i64) -> Result<(), Error> {
        let r = self
            .rpc(json!({"jsonrpc":"2.0","id":id,"method":"tools/list"}))
            .await?;
        assert_eq!(
            r["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["search", "describe", "invoke"]
        );
        let found=self.rpc(json!({"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"search","arguments":{"query":"read"}}})).await?;
        let found: Value =
            serde_json::from_str(found["result"]["content"][0]["text"].as_str().unwrap())?;
        let entry = found["matches"][0].clone();
        let d=self.rpc(json!({"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"describe","arguments":{"handle":entry["handle"]}}})).await?;
        let d: Value = serde_json::from_str(d["result"]["content"][0]["text"].as_str().unwrap())?;
        assert_eq!(d["input_schema"]["properties"]["ticket"]["type"], "string");
        assert_eq!(d["contract_digest"], entry["contract_digest"]);
        *self.described.lock().unwrap() = Some(entry);
        Ok(())
    }
    async fn rpc(&self, body: Value) -> Result<Value, Error> {
        let text = self
            .request(reqwest::Method::POST)
            .json(&body)
            .send()
            .await?
            .text()
            .await?;
        Ok(serde_json::from_str(
            text.lines()
                .find_map(|l| l.strip_prefix("data: "))
                .unwrap_or(&text),
        )?)
    }
}
