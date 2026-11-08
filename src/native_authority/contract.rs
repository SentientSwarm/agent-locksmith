use super::{Error, Result, schema};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>> {
    let obj = value.as_object().ok_or(Error("object_required"))?;
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(Error("unsupported_member"));
    }
    Ok(obj)
}
pub fn text(value: &Value, max: usize) -> Result<&str> {
    let text = value.as_str().ok_or(Error("string_required"))?;
    if text.is_empty() || text.len() > max || text.chars().any(char::is_control) {
        return Err(Error("invalid_string"));
    }
    Ok(text)
}
pub fn bounded_text(value: &Value, max: usize) -> Result<()> {
    if value.as_str().is_some_and(|v| v.len() <= max) {
        Ok(())
    } else {
        Err(Error("invalid_string"))
    }
}
pub fn tool(value: &Value) -> Result<()> {
    let obj = object(
        value,
        &[
            "name",
            "title",
            "description",
            "inputSchema",
            "outputSchema",
            "annotations",
        ],
    )?;
    text(obj.get("name").ok_or(Error("name_required"))?, 128)?;
    for (key, limit) in [("title", 128), ("description", 2048)] {
        if let Some(v) = obj.get(key) {
            bounded_text(v, limit)?;
        }
    }
    schema::root(
        obj.get("inputSchema")
            .ok_or(Error("input_schema_required"))?,
    )?;
    if let Some(v) = obj.get("outputSchema") {
        schema::root(v)?;
    }
    if let Some(v) = obj.get("annotations") {
        annotations(v)?;
    }
    Ok(())
}
fn annotations(value: &Value) -> Result<()> {
    let obj = object(
        value,
        &[
            "title",
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ],
    )?;
    for (key, v) in obj {
        if key == "title" {
            bounded_text(v, 128)?;
        } else if !v.is_boolean() {
            return Err(Error("annotation_type"));
        }
    }
    Ok(())
}
pub fn digest(domain: &str, value: &Value) -> String {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(&sorted(value)).expect("JSON value"));
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(o) => {
            let mut keys: Vec<_> = o.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|k| (k.clone(), sorted(&o[k])))
                    .collect(),
            )
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
        _ => value.clone(),
    }
}
pub fn observed(value: &Value) -> String {
    digest("locksmith-native-tool-v1", value)
}
pub fn review(value: &Value, effect: &str) -> Result<Value> {
    if !matches!(effect, "read" | "write" | "mixed") {
        return Err(Error("invalid_effect"));
    }
    tool(value)?;
    Ok(json!({"tool":value,"context":{},"effect":effect,"retry":"never"}))
}
pub fn screen(value: &Value, secret: &str) -> Result<()> {
    if secret.is_empty() {
        return Err(Error("credential_unresolved"));
    }
    let leaked = match value {
        Value::String(v) => v.contains(secret),
        Value::Array(a) => a.iter().any(|v| screen(v, secret).is_err()),
        Value::Object(o) => o
            .iter()
            .any(|(k, v)| k.contains(secret) || screen(v, secret).is_err()),
        _ => false,
    };
    if leaked {
        Err(Error("upstream_secret_echo"))
    } else {
        Ok(())
    }
}
