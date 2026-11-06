use super::{Error, Result, contract, values};
use serde_json::Value;

pub fn validate(value: &Value) -> Result<()> {
    contract::object(value, &["content", "structuredContent", "isError"])?;
    if value.to_string().len() > 32 * 1024 {
        return Err(Error("result_limit"));
    }
    if value.get("isError").is_some_and(|v| !v.is_boolean())
        || value
            .get("structuredContent")
            .is_some_and(|v| !v.is_object())
    {
        return Err(Error("result_type"));
    }
    let content = value["content"].as_array().ok_or(Error("result_content"))?;
    if content.len() > 16 {
        return Err(Error("result_limit"));
    }
    for item in content {
        contract::object(item, &["type", "text"])?;
        if item["type"] != "text" {
            return Err(Error("result_content"));
        }
        contract::bounded_text(&item["text"], 16 * 1024)?;
    }
    Ok(())
}
pub fn checked(tool: &Value, value: &Value) -> Result<()> {
    validate(value)?;
    if value["isError"] != true
        && let Some(schema) = tool.get("outputSchema")
    {
        values::validate(schema, &value["structuredContent"])?;
    }
    Ok(())
}
pub fn envelope(value: &Value) -> std::result::Result<(), locksmith_mcp_transport::Error> {
    raw(value).map_err(|_| locksmith_mcp_transport::Error("call_response_invalid"))
}
pub fn hosted_envelope(value: &Value) -> std::result::Result<(), locksmith_mcp_transport::Error> {
    if super::wire_format::notification(value) {
        super::wire_format::hosted_notification(value)
            .map_err(|_| locksmith_mcp_transport::Error("call_response_invalid"))
    } else {
        envelope(value)
    }
}
fn raw(value: &Value) -> Result<()> {
    if value
        .get("result")
        .is_some_and(|r| r.get("content").is_some())
    {
        contract::object(value, &["jsonrpc", "id", "result"])?;
        if value["jsonrpc"] != "2.0" || value["id"].as_u64().is_none() {
            return Err(Error("upstream_protocol"));
        }
        validate(&value["result"])
    } else {
        super::wire_format::validate_inner(value)
    }
}
