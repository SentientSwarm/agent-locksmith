use axum::{
    Json,
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

use crate::app::AppState;
use crate::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path((tool_name, path)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let request_path = req.uri().path().to_string();
    let config = state.config.load();

    // Find the tool
    let tool = match config
        .active_tools()
        .into_iter()
        .find(|t| t.name == tool_name)
    {
        Some(t) => t,
        None => {
            audit_record(
                &state.audit,
                AuditEvent {
                    ts_ms: now_ms(),
                    event_class: EventClass::Proxy,
                    event: "tool_not_found".to_string(),
                    tool: Some(tool_name.clone()),
                    method: Some(method.as_str().to_string()),
                    path: Some(request_path.clone()),
                    status: Some(404),
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    decision: Decision::Denied,
                    ..AuditEvent::default()
                },
            )
            .await;
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": {
                        "message": format!("Unknown tool: {}", tool_name),
                        "type": "not_found"
                    }
                })),
            )
                .into_response();
        }
    };

    let upstream_url = format!("{}/{}", tool.upstream.trim_end_matches('/'), path);
    let upstream_host = url_host(&tool.upstream);
    let headers = req.headers().clone();
    let body_limit = usize::try_from(tool.body_limit_bytes).unwrap_or(usize::MAX);
    let body_bytes = match axum::body::to_bytes(req.into_body(), body_limit).await {
        Ok(b) => b,
        Err(_) => {
            audit_record(
                &state.audit,
                AuditEvent {
                    ts_ms: now_ms(),
                    event_class: EventClass::Proxy,
                    event: "request_body_read_error".to_string(),
                    tool: Some(tool_name.clone()),
                    upstream_host: upstream_host.clone(),
                    method: Some(method.as_str().to_string()),
                    path: Some(request_path.clone()),
                    status: Some(400),
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    decision: Decision::Error,
                    ..AuditEvent::default()
                },
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": {"message": "Failed to read request body", "type": "bad_request"}})),
            )
                .into_response();
        }
    };

    let client = state.client_pool.get_or_build(tool, &config);
    let mut upstream_req = client.request(method.clone(), &upstream_url);

    // Forward headers, stripping auth-related ones
    let auth_header_name = tool.auth.as_ref().map(|a| a.header.to_lowercase());
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_lowercase();
        if lower == "host"
            || lower == "authorization"
            || lower == "x-api-key"
            || auth_header_name.as_deref() == Some(&lower)
        {
            continue;
        }
        upstream_req = upstream_req.header(name, value);
    }

    // Inject configured credentials. Reads from the resolved-creds
    // snapshot (M5 / T5.1) — daemon resolves SecretRefs once at
    // startup, proxy never touches the raw SecretRef on the hot path.
    if let Some(auth) = &tool.auth {
        let resolved = state.resolved_creds.load();
        if let Some(value) = resolved.get(&tool.name) {
            upstream_req =
                upstream_req.header(&auth.header, secrecy::ExposeSecret::expose_secret(value));
        } else {
            // Tool declared auth but no credential resolved — degraded
            // mode. Fall through without injection; upstream returns 401
            // and we record the proxy-side audit row as before.
        }
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes);
    }

    match upstream_req.send().await {
        Ok(resp) => {
            let upstream_status = resp.status().as_u16();
            let status = StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response_headers = HeaderMap::new();
            for (name, value) in resp.headers() {
                // Skip hop-by-hop headers that are bound to the upstream
                // connection's transport framing — the body is rebuilt as
                // an axum stream below, so axum/hyper sets these afresh.
                let lower = name.as_str().to_ascii_lowercase();
                if lower == "transfer-encoding"
                    || lower == "content-length"
                    || lower == "connection"
                    || lower == "keep-alive"
                    || lower == "proxy-connection"
                    || lower == "upgrade"
                    || lower == "te"
                    || lower == "trailer"
                {
                    continue;
                }
                if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
                    response_headers.insert(name.clone(), v);
                }
            }
            let decision = if upstream_status >= 500 {
                Decision::Error
            } else {
                Decision::Allowed
            };
            audit_record(
                &state.audit,
                AuditEvent {
                    ts_ms: now_ms(),
                    event_class: EventClass::Proxy,
                    event: "proxy_request".to_string(),
                    tool: Some(tool_name.clone()),
                    upstream_host: upstream_host.clone(),
                    method: Some(method.as_str().to_string()),
                    path: Some(request_path.clone()),
                    status: Some(upstream_status),
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    decision,
                    ..AuditEvent::default()
                },
            )
            .await;
            // Stream the upstream body to the agent rather than buffering
            // (R-N6: ≤100ms first-byte added latency). T1.2 closes T1.1.
            let body = Body::from_stream(resp.bytes_stream());
            let mut response = Response::new(body);
            *response.status_mut() = status;
            *response.headers_mut() = response_headers;
            response
        }
        Err(e) => {
            let (status, kind) = if e.is_timeout() {
                (StatusCode::GATEWAY_TIMEOUT, "timeout")
            } else {
                (StatusCode::BAD_GATEWAY, "upstream_error")
            };
            audit_record(
                &state.audit,
                AuditEvent {
                    ts_ms: now_ms(),
                    event_class: EventClass::Proxy,
                    event: kind.to_string(),
                    tool: Some(tool_name.clone()),
                    upstream_host,
                    method: Some(method.as_str().to_string()),
                    path: Some(request_path.clone()),
                    status: Some(status.as_u16()),
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    decision: Decision::Error,
                    ..AuditEvent::default()
                },
            )
            .await;
            (
                status,
                Json(json!({"error": {"message": match kind {
                    "timeout" => "Upstream timeout",
                    _ => "Upstream error",
                }, "type": kind}})),
            )
                .into_response()
        }
    }
}

/// Best-effort audit write. Errors are logged and swallowed — audit must
/// never block proxy traffic (INF-26).
async fn audit_record(audit: &Option<AuditRepository>, event: AuditEvent) {
    let Some(repo) = audit else {
        return;
    };
    if let Err(e) = repo.record(&event).await {
        tracing::warn!(error = %e, event = %event.event, "audit write failed");
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn url_host(url: &str) -> Option<String> {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = stripped.split(['/', ':']).next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}
