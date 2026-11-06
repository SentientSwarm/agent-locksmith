//! Finite observation and admitted calls through the accepted bounded client hook.
use super::wire_format::{response, validate_mode};
pub use super::wire_format::{validate, validate_hosted};
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
    pub selected_tools: Option<&'a [String]>,
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
            let mut manifest = append_page(&result, &mut tools, &mut names, self.selected_tools)?;
            cursor = result
                .get("nextCursor")
                .filter(|v| self.selected_tools.is_none() || !v.is_null())
                .map(|v| contract::text(v, 1024).map(str::to_owned))
                .transpose()?;
            let Some(next) = cursor.as_ref() else {
                if let Some(selected) = self.selected_tools {
                    if selected.iter().any(|n| !names.contains(n)) {
                        return Err(Error("selected_tool_missing"));
                    }
                    manifest["projection"] = json!({"policy":"explicit_profile_tools_v1", "total":names.len(),"selected":tools.len(),"omitted":names.len()-tools.len()});
                    if manifest.to_string().len() > 48 * 1024 {
                        return Err(Error("manifest_limit"));
                    }
                }
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
        let (value, session) = response(reply, self.selected_tools.is_some()).await?;
        if method == "tools/call" {
            super::call_result::envelope(&value).map_err(|_| Error("upstream_result"))?;
        } else {
            validate_mode(&value, self.selected_tools.is_some())?;
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
    selected: Option<&[String]>,
) -> Result<Value> {
    let list = result["tools"].as_array().ok_or(Error("upstream_tools"))?;
    for tool in list {
        let name = tool["name"].as_str().ok_or(Error("upstream_tools"))?;
        if names.len() >= if selected.is_some() { 256 } else { 32 }
            || !names.insert(name.to_owned())
        {
            return Err(Error("manifest_limit"));
        }
        if selected.is_some_and(|s| !s.iter().any(|n| n == name)) {
            continue;
        }
        contract::tool(tool)?;
        tools.push(json!({"tool":tool,"observed_digest":contract::observed(tool)}));
    }
    let manifest = json!({"tools":&tools});
    if manifest.to_string().len() > 48 * 1024 {
        return Err(Error("manifest_limit"));
    }
    Ok(manifest)
}

#[cfg(test)]
mod hosted_tests {
    use super::*;
    fn tool(name: &str) -> Value {
        json!({"name":name,"inputSchema":{"type":"object","properties":{},"additionalProperties":false}})
    }
    #[test]
    fn hosted_complete_catalog_projection_keeps_exact_selected_contract() {
        let selected = vec!["selected".to_string()];
        let mut page = json!({"tools":[tool("selected")]});
        for i in 0..255 {
            page["tools"].as_array_mut().unwrap().push(
                json!({"name":format!("omit_{i}"),"inputSchema":{"anyOf":[{"type":"string"}]}}),
            );
        }
        let envelope = |p: &Value| json!({"jsonrpc":"2.0","id":2,"result":p});
        assert!(validate_hosted(&envelope(&page)).is_ok());
        assert!(
            validate(&envelope(&page)).is_err(),
            "manual remains 32/full grammar"
        );
        let (mut tools, mut names) = (vec![], BTreeSet::new());
        let manifest = append_page(&page, &mut tools, &mut names, Some(&selected)).unwrap();
        assert_eq!(names.len(), 256);
        assert_eq!(
            manifest["tools"],
            json!([{"tool":tool("selected"),"observed_digest":contract::observed(&tool("selected"))}])
        );
        assert!(
            append_page(
                &json!({"tools":[tool("over")] }),
                &mut tools,
                &mut names,
                Some(&selected)
            )
            .is_err()
        );
        let (mut tools, mut names) = (vec![], BTreeSet::new());
        append_page(
            &json!({"tools":[tool("omit")] }),
            &mut tools,
            &mut names,
            Some(&selected),
        )
        .unwrap();
        assert!(
            append_page(
                &json!({"tools":[tool("omit")] }),
                &mut tools,
                &mut names,
                Some(&selected)
            )
            .is_err(),
            "omitted duplicate across pages"
        );
        let mut bad = tool("selected");
        bad["inputSchema"] = json!({"anyOf":[{"type":"string"}]});
        assert!(
            append_page(
                &json!({"tools":[bad]}),
                &mut vec![],
                &mut BTreeSet::new(),
                Some(&selected)
            )
            .is_err(),
            "selected unsupported schema never normalized"
        );
        for field in ["annotations", "title", "unknown"] {
            let mut bad = tool("selected");
            bad[field] = Value::Null;
            assert!(
                validate_hosted(&envelope(&json!({"tools":[bad]}))).is_err(),
                "SDK loss {field}"
            );
        }
    }
}
