use super::{Error, Result, contract, policy::Policy};
use futures_util::StreamExt;
use locksmith_mcp_transport::{Error as WireError, strict_json};
use rmcp::transport::streamable_http_client::StreamableHttpPostResponse as Reply;
use serde_json::Value;
pub fn validate(value: &Value) -> std::result::Result<(), WireError> {
    validate_inner(value).map_err(|_| WireError("observation_response_invalid"))
}
pub(super) fn validate_inner(value: &Value) -> Result<()> {
    validate_mode(value, false)
}
pub fn validate_v2(value: &Value) -> std::result::Result<(), WireError> {
    validate_selection(value, false, Policy::V2, false)
        .map_err(|_| WireError("observation_response_invalid"))
}
pub fn validate_selected_v2(value: &Value) -> std::result::Result<(), WireError> {
    validate_selection(value, false, Policy::V2, true)
        .map_err(|_| WireError("observation_response_invalid"))
}
pub fn validate_hosted(value: &Value) -> std::result::Result<(), WireError> {
    validate_mode(value, true).map_err(|_| WireError("observation_response_invalid"))
}
pub(super) fn notification(value: &Value) -> bool {
    value.get("id").is_none() && value.get("method").is_some()
}
pub(super) fn hosted_notification(value: &Value) -> Result<()> {
    contract::object(value, &["jsonrpc", "method", "params"])?;
    if value["jsonrpc"] != "2.0"
        || !contract::text(&value["method"], 128)?.starts_with("notifications/")
        || value.get("params").is_some_and(|p| !p.is_object())
    {
        return Err(Error("upstream_protocol"));
    }
    Ok(())
}
pub(super) fn validate_mode(value: &Value, hosted: bool) -> Result<()> {
    validate_policy(value, hosted, Policy::V1)
}
pub(super) fn validate_policy(value: &Value, hosted: bool, policy: Policy) -> Result<()> {
    validate_selection(value, hosted, policy, hosted)
}
pub(super) fn validate_selection(
    value: &Value,
    hosted: bool,
    policy: Policy,
    selected: bool,
) -> Result<()> {
    if hosted && notification(value) {
        return hosted_notification(value);
    }
    contract::object(value, &["jsonrpc", "id", "result"])?;
    if value["jsonrpc"] != "2.0" || value["id"].as_u64().is_none() {
        return Err(Error("upstream_protocol"));
    }
    let result = value.get("result").ok_or(Error("upstream_result"))?;
    if result.get("tools").is_some() {
        list(result, hosted, policy, selected)
    } else {
        initialize(result)
    }
}
fn list(result: &Value, hosted: bool, policy: Policy, selected: bool) -> Result<()> {
    contract::object(result, &["tools", "nextCursor"])?;
    let tools = result["tools"].as_array().ok_or(Error("upstream_tools"))?;
    if tools.len() > if selected { 256 } else { 32 } {
        return Err(Error("manifest_limit"));
    }
    for tool in tools {
        if hosted || policy == Policy::V2 {
            contract::text(&tool["name"], 128)?;
            // Preserve the actual JSON tool, before SDK normalization can drop fields.
            let decoded: rmcp::model::Tool =
                serde_json::from_value(tool.clone()).map_err(|_| Error("upstream_tools"))?;
            if serde_json::to_value(decoded).map_err(|_| Error("upstream_tools"))? != *tool {
                return Err(Error("upstream_tools"));
            }
        }
        if !selected {
            contract::tool_with(tool, policy)?;
        }
    }
    if let Some(cursor) = result.get("nextCursor").filter(|v| !hosted || !v.is_null()) {
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
pub(super) async fn response(reply: Reply, hosted: bool) -> Result<(Value, Option<String>)> {
    match reply {
        Reply::Json(message, session) => Ok((
            serde_json::to_value(message).map_err(|_| Error("upstream_result"))?,
            session,
        )),
        Reply::Sse(mut events, session) => {
            let mut response = None;
            let mut count = 0;
            while let Some(event) = events.next().await {
                count += 1;
                if count > 128 {
                    return Err(Error("upstream_stream"));
                }
                let event = event.map_err(|e| {
                    Error(locksmith_mcp_transport::io_code(&e).unwrap_or("upstream_stream"))
                })?;
                if let Some(data) = event.data.filter(|d| !d.is_empty()) {
                    let value = strict_json::parse(data.as_bytes(), Default::default())
                        .map_err(|_| Error("upstream_json"))?;
                    if hosted {
                        if notification(&value) {
                            hosted_notification(&value)?;
                            continue;
                        }
                        // The first response ends this owned stream. No claim about its tail/EOF.
                        return Ok((value, session));
                    }
                    if response.is_some() {
                        return Err(Error("upstream_extra_message"));
                    }
                    response = Some(value);
                }
            }
            Ok((response.ok_or(Error("upstream_result"))?, session))
        }
        _ => Err(Error("upstream_result")),
    }
}
