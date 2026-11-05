use super::{Runtime, context::Context, error::Failure, wire};
use axum::{extract::Request, http::HeaderMap};
use rmcp::transport::streamable_http_server::session::SessionId;
use serde_json::Value;
use std::sync::{Arc, atomic::Ordering};

pub(super) fn select(
    runtime: &Runtime,
    candidate: Arc<Context>,
    req: &Request,
    value: Option<&Value>,
) -> Result<Arc<Context>, Failure> {
    let scoped = runtime
        .pool
        .scoped(
            candidate.scope.clone(),
            candidate.clone(),
            candidate.cancelled.clone(),
        )
        .map_err(|_| Failure(503, "native_scope_unavailable"))?;
    if value.is_some_and(|v| v["method"] == "initialize") {
        return initialize(runtime, candidate, req.headers());
    }
    let id = existing(req.headers())?;
    let context = scoped
        .metadata(&SessionId::from(id))
        .map_err(|_| Failure(404, "session_unavailable"))?;
    ready(&context, value)?;
    Ok(context)
}
fn initialize(
    runtime: &Runtime,
    candidate: Arc<Context>,
    headers: &HeaderMap,
) -> Result<Arc<Context>, Failure> {
    if headers.contains_key("mcp-session-id") {
        return Err(Failure(400, "initialize_has_session"));
    }
    if wire::text(headers, "mcp-protocol-version").is_some_and(|v| v != wire::VERSION) {
        return Err(Failure(400, "protocol_version"));
    }
    let mut contexts = runtime.contexts.lock().unwrap();
    contexts.retain(|c| c.strong_count() > 0);
    contexts.push(Arc::downgrade(&candidate));
    Ok(candidate)
}
fn existing(headers: &HeaderMap) -> Result<&str, Failure> {
    if wire::text(headers, "mcp-protocol-version") != Some(wire::VERSION) {
        return Err(Failure(400, "protocol_version"));
    }
    wire::text(headers, "mcp-session-id")
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .ok_or(Failure(400, "session_required"))
}

fn ready(context: &Context, value: Option<&Value>) -> Result<(), Failure> {
    if !context.ready.load(Ordering::SeqCst)
        && value.is_some_and(|v| {
            !matches!(
                v["method"].as_str(),
                Some("notifications/initialized" | "ping")
            )
        })
    {
        return Err(Failure(400, "initialization_incomplete"));
    }
    Ok(())
}
