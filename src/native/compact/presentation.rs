use crate::native_authority::{Error, Result, call_result, effective::Approved};
use serde_json::{Value, json};

pub(super) fn result(payload: Value) -> Result<Value> {
    let result = json!({"content":[{"type":"text","text":payload.to_string()}],"isError":false});
    call_result::validate(&result).map_err(|_| Error("compact_response_limit"))?;
    Ok(result)
}
pub(super) fn summary(tool: &Value) -> String {
    let text = ["description", "title", "name"]
        .into_iter()
        .filter_map(|k| tool[k].as_str())
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or("Tool");
    let mut end = text.len().min(512);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
pub(super) fn signature(tool: &Value) -> String {
    let schema = &tool["inputSchema"];
    let required = schema["required"].as_array();
    let mut fields = schema["properties"]
        .as_object()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    fields.sort_by_key(|(name, _)| *name);
    let fields = fields
        .into_iter()
        .map(|(name, property)| {
            let mode = if required.is_some_and(|r| r.iter().any(|v| v.as_str() == Some(name))) {
                "required"
            } else {
                "optional"
            };
            format!(
                "{}: {} {mode}",
                json!(name),
                property["type"].as_str().unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("({fields})")
}
pub(super) fn describe(name: &str, tool: &Approved) -> Value {
    let mut value = json!({"name":name,"contract_digest":tool.digest,"input_schema":tool.public["inputSchema"],"output_schema":tool.public.get("outputSchema"),"effect":tool.effect,
        "usage":"Construct public arguments from input_schema, then invoke this handle with contract_digest. Operator-fixed inputs are omitted.",
        "limitations":["Current authority is rechecked before dispatch.","Unknown outcomes must not be automatically replayed."]});
    if !tool.policy.is_v1() {
        value["native_contract"] =
            tool.public["_meta"][crate::native_authority::policy::PUBLIC_MARKER].clone();
    }
    value
}
pub(super) fn tools() -> Vec<Value> {
    let reference =
        json!({"type":"string","pattern":"^[0-9a-f]{32}$","minLength":32,"maxLength":32});
    let search = json!({"name":"search","description":"Search the first-list pinned current approved inventory. Does not grant invocation or contact the upstream.","inputSchema":{"type":"object","properties":{"query":{"type":"string","minLength":1,"maxLength":256,"description":"Nonblank, no controls, at most 256 UTF-8 bytes."},"limit":{"type":"integer","minimum":1,"maximum":20,"default":5},"cursor":reference},"required":["query"],"additionalProperties":false}});
    let describe = json!({"name":"describe","description":"Read the complete public schema and effect before invoking a handle.","inputSchema":{"type":"object","properties":{"handle":reference},"required":["handle"],"additionalProperties":false}});
    let invoke = json!({"name":"invoke","description":"Invoke a previously described current handle through the ordinary committed native dispatcher. No automatic retry.","inputSchema":{"type":"object","properties":{"handle":reference,"contract_digest":{"type":"string","pattern":"^[0-9a-f]{64}$","minLength":64,"maxLength":64},"arguments":{"type":"object","additionalProperties":true}},"required":["handle","contract_digest","arguments"],"additionalProperties":false}});
    vec![search, describe, invoke]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escaped_outer_result_has_an_independent_limit() {
        let payload = json!("\\".repeat(8190));
        assert!(payload.to_string().len() <= 16 * 1024);
        assert_eq!(result(payload).unwrap_err().0, "compact_response_limit");
        assert!(result(json!("small")).is_ok());
    }
}
