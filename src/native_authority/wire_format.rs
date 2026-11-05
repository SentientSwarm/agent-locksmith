use super::{Error, Result, contract};
use futures_util::StreamExt;
use locksmith_mcp_transport::{Error as WireError, strict_json};
use rmcp::transport::streamable_http_client::StreamableHttpPostResponse as Reply;
use serde_json::Value;
pub fn validate(value: &Value) -> std::result::Result<(), WireError> {
    validate_inner(value).map_err(|_| WireError("observation_response_invalid"))
}
pub(super) fn validate_inner(value: &Value) -> Result<()> {
    contract::object(value, &["jsonrpc", "id", "result"])?;
    if value["jsonrpc"] != "2.0" || value["id"].as_u64().is_none() {
        return Err(Error("upstream_protocol"));
    }
    let result = value.get("result").ok_or(Error("upstream_result"))?;
    if result.get("tools").is_some() {
        list(result)
    } else {
        initialize(result)
    }
}
fn list(result: &Value) -> Result<()> {
    contract::object(result, &["tools", "nextCursor"])?;
    let tools = result["tools"].as_array().ok_or(Error("upstream_tools"))?;
    if tools.len() > 32 {
        return Err(Error("manifest_limit"));
    }
    for tool in tools {
        contract::tool(tool)?;
    }
    if let Some(cursor) = result.get("nextCursor") {
        contract::text(cursor, 1024)?;
    }
    Ok(())
}
fn initialize(result: &Value) -> Result<()> {
    contract::object(
        result,
        &[
            "protocolVersion",
            "capabilities",
            "serverInfo",
            "instructions",
        ],
    )?;
    if result["protocolVersion"] != crate::registrations::protocol::VERSION
        || !result["capabilities"].is_object()
        || !result["serverInfo"].is_object()
    {
        return Err(Error("upstream_initialize"));
    }
    Ok(())
}
pub(super) async fn response(reply: Reply) -> Result<(Value, Option<String>)> {
    match reply {
        Reply::Json(message, session) => Ok((
            serde_json::to_value(message).map_err(|_| Error("upstream_result"))?,
            session,
        )),
        Reply::Sse(mut events, session) => {
            let mut response = None;
            while let Some(event) = events.next().await {
                let event = event.map_err(|_| Error("upstream_stream"))?;
                if let Some(data) = event.data.filter(|d| !d.is_empty()) {
                    if response.is_some() {
                        return Err(Error("upstream_extra_message"));
                    }
                    response = Some(
                        strict_json::parse(data.as_bytes(), Default::default())
                            .map_err(|_| Error("upstream_json"))?,
                    );
                }
            }
            Ok((response.ok_or(Error("upstream_result"))?, session))
        }
        _ => Err(Error("upstream_result")),
    }
}
