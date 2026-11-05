//! Finite observation and admitted calls through the accepted bounded client hook.
pub use super::wire_format::validate;
use super::wire_format::{response, validate_inner};
use super::{Error, Result, contract};
use locksmith_mcp_transport::Client;
use rmcp::{
    model::ClientJsonRpcMessage,
    transport::streamable_http_client::{
        StreamableHttpClient, StreamableHttpPostResponse as Reply,
    },
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

pub struct Connection<'a> {
    pub client: Client,
    pub endpoint: Arc<str>,
    pub bearer: Option<&'a str>,
    pub session: Option<Arc<str>>,
}
impl Connection<'_> {
    pub async fn initialize(&mut self) -> Result<()> {
        self.rpc(
            1,
            "initialize",
            json!({"protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"locksmith-observer","version":"1"}}),
        )
        .await?;
        let message: ClientJsonRpcMessage =
            serde_json::from_value(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
                .map_err(|_| Error("request_invalid"))?;
        let reply = self.send(message).await?;
        if !matches!(reply, Reply::Accepted) {
            return Err(Error("upstream_notification"));
        }
        Ok(())
    }
    pub async fn observe(&mut self) -> Result<Value> {
        self.initialize().await?;
        self.pages().await
    }
    pub async fn call(&mut self, name: &str, arguments: &Value) -> Result<Value> {
        self.rpc(2, "tools/call", json!({"name":name,"arguments":arguments}))
            .await
    }
    async fn pages(&mut self) -> Result<Value> {
        let mut cursor = None;
        let mut cursors = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut tools = Vec::new();
        for page in 0..4 {
            let params = cursor
                .as_ref()
                .map(|v| json!({"cursor":v}))
                .unwrap_or(json!({}));
            let result = self.rpc(page + 2, "tools/list", params).await?;
            let manifest = append_page(&result, &mut tools, &mut names)?;
            cursor = result
                .get("nextCursor")
                .map(|v| contract::text(v, 1024).map(str::to_owned))
                .transpose()?;
            let Some(next) = cursor.as_ref() else {
                return Ok(manifest);
            };
            if !cursors.insert(next.clone()) {
                return Err(Error("cursor_repeated"));
            }
        }
        Err(Error("page_limit"))
    }
    async fn rpc(&mut self, id: u64, method: &str, params: Value) -> Result<Value> {
        let message = serde_json::from_value(
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
        )
        .map_err(|_| Error("request_invalid"))?;
        let reply = self.send(message).await?;
        let (value, session) = response(reply).await?;
        if method == "tools/call" {
            super::call_result::envelope(&value).map_err(|_| Error("upstream_result"))?;
        } else {
            validate_inner(&value)?;
        }
        if value["id"] != id
            || (method == "initialize" && value["result"].get("protocolVersion").is_none())
            || (method == "tools/list" && value["result"].get("tools").is_none())
        {
            return Err(Error("upstream_id"));
        }
        if let Some(bearer) = self.bearer {
            contract::screen(&value, bearer)?;
        }
        self.session(method, session)?;
        Ok(value["result"].clone())
    }
    fn session(&mut self, method: &str, session: Option<String>) -> Result<()> {
        if method != "initialize" && session.is_some() && self.session.is_none() {
            return Err(Error("upstream_session"));
        }
        if let Some(session) = session {
            if self
                .session
                .as_ref()
                .is_some_and(|old| old.as_ref() != session)
            {
                return Err(Error("upstream_session"));
            }
            self.session = Some(session.into());
        }
        Ok(())
    }
    async fn send(&self, message: ClientJsonRpcMessage) -> Result<Reply> {
        self.client
            .post_message_with_max_sse_event_size(
                self.endpoint.clone(),
                message,
                self.session.clone(),
                self.bearer.map(str::to_owned),
                headers(),
                64 * 1024,
            )
            .await
            .map_err(|_| Error("upstream_observation_failed"))
    }
    pub async fn cleanup(&self) {
        if let Some(session) = &self.session {
            let _ = self
                .client
                .delete_session(
                    self.endpoint.clone(),
                    session.clone(),
                    self.bearer.map(str::to_owned),
                    headers(),
                )
                .await;
        }
    }
}
fn headers() -> HashMap<axum::http::HeaderName, axum::http::HeaderValue> {
    HashMap::from([(
        axum::http::HeaderName::from_static("mcp-protocol-version"),
        axum::http::HeaderValue::from_static("2025-11-25"),
    )])
}
fn append_page(
    result: &Value,
    tools: &mut Vec<Value>,
    names: &mut BTreeSet<String>,
) -> Result<Value> {
    let list = result["tools"].as_array().ok_or(Error("upstream_tools"))?;
    for tool in list {
        let name = tool["name"].as_str().ok_or(Error("upstream_tools"))?;
        if tools.len() >= 32 || !names.insert(name.to_owned()) {
            return Err(Error("manifest_limit"));
        }
        tools.push(json!({"tool":tool,"observed_digest":contract::observed(tool)}));
    }
    let manifest = json!({"tools":&tools});
    if manifest.to_string().len() > 48 * 1024 {
        return Err(Error("manifest_limit"));
    }
    Ok(manifest)
}
