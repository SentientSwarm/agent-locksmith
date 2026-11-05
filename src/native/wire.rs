use super::{
    config::{Config, origin},
    error::Failure,
};
use axum::http::{HeaderMap, Method};
use serde_json::Value;

pub(super) const VERSION: &str = crate::registrations::protocol::VERSION;
pub(super) fn headers(h: &HeaderMap, method: &Method, cfg: &Config) -> Result<(), Failure> {
    if h.len() > 64
        || h.iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum::<usize>()
            > 16384
    {
        return Err(Failure(431, "headers_too_large"));
    }
    for name in [
        "authorization",
        "host",
        "origin",
        "content-type",
        "content-length",
        "mcp-session-id",
        "mcp-protocol-version",
        "last-event-id",
    ] {
        if h.get_all(name).iter().count() > 1 {
            return Err(Failure(400, "duplicate_header"));
        }
    }
    origins(h, cfg)?;
    media(h, method)?;
    if h.contains_key("last-event-id") {
        return Err(Failure(400, "resume_unsupported"));
    }
    Ok(())
}
fn origins(h: &HeaderMap, cfg: &Config) -> Result<(), Failure> {
    if let Some(value) = h.get("origin") {
        let value = value
            .to_str()
            .ok()
            .and_then(origin)
            .ok_or(Failure(403, "origin_denied"))?;
        if !cfg
            .allowed_origins
            .iter()
            .any(|s| origin(s).as_ref() == Some(&value))
        {
            return Err(Failure(403, "origin_denied"));
        }
    }
    let host = text(h, "host").ok_or(Failure(400, "host_required"))?;
    if !cfg
        .allowed_hosts
        .iter()
        .any(|allowed| host_matches(host, allowed))
    {
        return Err(Failure(403, "host_denied"));
    }
    Ok(())
}
fn host_matches(raw: &str, allowed: &str) -> bool {
    if origin(&format!("https://{raw}")).is_none() {
        return false;
    }
    let (Ok(raw), Ok(allowed)) = (
        raw.parse::<axum::http::uri::Authority>(),
        allowed.parse::<axum::http::uri::Authority>(),
    ) else {
        return false;
    };
    raw.host().eq_ignore_ascii_case(allowed.host())
        && allowed
            .port_u16()
            .is_none_or(|port| raw.port_u16() == Some(port))
}
fn media(h: &HeaderMap, method: &Method) -> Result<(), Failure> {
    if method != Method::POST && method != Method::GET && method != Method::DELETE {
        return Err(Failure(405, "method_not_allowed"));
    }
    let accepts = |mime| {
        text(h, "accept").is_some_and(|s| {
            s.split(',')
                .any(|m| m.split(';').next().unwrap().trim() == mime)
        })
    };
    if method == Method::POST {
        if text(h, "content-type").and_then(|s| s.split(';').next()) != Some("application/json") {
            return Err(Failure(415, "content_type"));
        }
        if !accepts("application/json") || !accepts("text/event-stream") {
            return Err(Failure(406, "accept"));
        }
    }
    if method == Method::GET && !accepts("text/event-stream") {
        return Err(Failure(406, "accept"));
    }
    Ok(())
}
pub(super) fn text<'a>(h: &'a HeaderMap, key: &str) -> Option<&'a str> {
    h.get(key)?.to_str().ok()
}
pub(super) fn id(value: &Value) -> bool {
    match value {
        Value::String(s) => !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control),
        Value::Number(n) => n
            .as_i64()
            .is_some_and(|n| n.unsigned_abs() <= 9_007_199_254_740_991),
        _ => false,
    }
}
pub(super) fn envelope(v: &Value) -> Result<&str, (i64, &'static str)> {
    let bad = (-32600, "invalid_request");
    let object = v.as_object().ok_or(bad)?;
    if v["jsonrpc"] != "2.0"
        || object
            .keys()
            .any(|k| !["jsonrpc", "id", "method", "params"].contains(&k.as_str()))
    {
        return Err(bad);
    }
    let method = v["method"].as_str().ok_or(bad)?;
    let notification = method.starts_with("notifications/");
    if notification == v.get("id").is_some() || v.get("id").is_some_and(|v| !id(v)) {
        return Err(bad);
    }
    let keys = match method {
        "initialize" => &["protocolVersion", "capabilities", "clientInfo"][..],
        "ping" | "notifications/initialized" => &[],
        "tools/list" => &["cursor"],
        "tools/call" => &["name", "arguments"],
        "notifications/cancelled" => &["requestId", "reason"],
        _ => return Err((-32601, "method_not_found")),
    };
    parameter_keys(v, keys, notification)?;
    params(v, method)?;
    Ok(method)
}
fn parameter_keys(v: &Value, keys: &[&str], notification: bool) -> Result<(), (i64, &'static str)> {
    if let Some(params) = v.get("params") {
        let p = params.as_object().ok_or((-32602, "invalid_params"))?;
        if p.keys()
            .any(|k| !(keys.contains(&k.as_str()) || k == "_meta" && !notification))
            || p.get("_meta").is_some_and(|m| !metadata(m))
        {
            return Err((-32602, "invalid_params"));
        }
    }
    Ok(())
}
fn metadata(value: &Value) -> bool {
    value.as_object().is_some_and(|m| {
        m.iter()
            .all(|(key, value)| key == "progressToken" && id(value))
    })
}
fn params(v: &Value, method: &str) -> Result<(), (i64, &'static str)> {
    let p = &v["params"];
    let valid = match method {
        "initialize" => initialize(p),
        "tools/list" => p.get("cursor").is_none(),
        "tools/call" => {
            p["name"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 128)
                && p.get("arguments").is_none_or(Value::is_object)
        }
        "notifications/cancelled" => {
            id(&p["requestId"])
                && p.get("reason")
                    .is_none_or(|v| v.as_str().is_some_and(|s| s.len() <= 256))
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err((-32602, "invalid_params"))
    }
}

fn initialize(p: &Value) -> bool {
    p["protocolVersion"] == VERSION
        && p["capabilities"].as_object().is_some_and(|p| p.is_empty())
        && p["clientInfo"]["name"]
            .as_str()
            .is_some_and(|s| s.len() <= 128)
        && p["clientInfo"]["version"]
            .as_str()
            .is_some_and(|s| s.len() <= 64)
}
