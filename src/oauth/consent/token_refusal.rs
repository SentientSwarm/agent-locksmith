//! Token-only attribution of an already-refused response, never acceptance.
use super::parse;
use serde_json::Value;

pub(super) fn bytes(bytes: &[u8], known: Option<&str>, fallback: &'static str) -> &'static str {
    parse(bytes).map_or(fallback, |v| value(&v, known, fallback))
}
pub(super) fn value(v: &Value, known: Option<&str>, fallback: &'static str) -> &'static str {
    let Some(object) = v.as_object() else {
        return fallback;
    };
    if object.get("error").and_then(Value::as_str) != Some("bad_code_verifier")
        || object.keys().any(|k| k != "error" && k != "ok")
        || object.get("ok").is_some_and(|v| v != false)
        || known.is_some_and(|secret| {
            object
                .iter()
                .any(|(k, v)| k.contains(secret) || v.as_str().is_some_and(|s| s.contains(secret)))
        })
    {
        return fallback;
    }
    "token_verifier_refused"
}
