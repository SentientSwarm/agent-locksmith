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
use crate::response_controls::{ApplyOutcome, ResponseControls, SizeCappedStream};

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path((tool_name, path)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let request_path = req.uri().path().to_string();
    let config = state.config.load();
    // Resolve auth_method + agent identity for audit (#67 / T6.10 / M9).
    // The auth middleware stamps `AuthenticatedAs` and (under per-agent
    // bearer or mTLS) the resolved `AgentIdentity` into request extensions.
    let auth_method_str = match req.extensions().get::<crate::auth::AuthenticatedAs>() {
        Some(crate::auth::AuthenticatedAs::Mtls) => "mtls",
        _ => "bearer",
    };
    let agent_identity = req
        .extensions()
        .get::<crate::auth_v2::AgentIdentity>()
        .cloned();
    let agent_public_id: Option<String> = agent_identity.as_ref().map(|id| id.public_id.clone());

    // M9 ACL gate. When the request carries an AgentIdentity (per-agent
    // bearer or mTLS), enforce the agent's tool_allowlist /
    // tool_denylist before reaching the tool resolver. Identity-less
    // requests reach this code only in M0/M1 deployments without admin
    // substrate (preserved for back-compat).
    if let Some(identity) = agent_identity.as_ref()
        && let Err(reason) = check_tool_acl(identity, &tool_name)
    {
        return record_authz_denied(
            &state.audit,
            &tool_name,
            method.as_str(),
            &request_path,
            started,
            auth_method_str,
            &agent_public_id,
            reason,
        )
        .await;
    }

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
                    auth_method: Some(auth_method_str.to_string()),
                    agent_public_id: agent_public_id.clone(),
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
                    auth_method: Some(auth_method_str.to_string()),
                    agent_public_id: agent_public_id.clone(),
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
            // Snapshot upstream Content-Type before consuming the
            // response — needed for response-controls dispatch and
            // for the response we hand to the agent.
            let upstream_content_type = resp
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
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
            // M7 / T7.2-T7.4: per-tool response controls.
            let rc = state.response_controls.get(&tool_name).cloned();
            if let Some(rc) = rc.as_ref() {
                // Content-type allowlist (T7.2 streaming pre-check).
                if !rc.streaming_content_type_allowed(upstream_content_type.as_deref()) {
                    audit_record(
                        &state.audit,
                        AuditEvent {
                            ts_ms: now_ms(),
                            event_class: EventClass::Proxy,
                            event: "response_content_type_disallowed".to_string(),
                            tool: Some(tool_name.clone()),
                            upstream_host: upstream_host.clone(),
                            method: Some(method.as_str().to_string()),
                            path: Some(request_path.clone()),
                            status: Some(502),
                            latency_ms: Some(started.elapsed().as_millis() as u64),
                            decision: Decision::Denied,
                            auth_method: Some(auth_method_str.to_string()),
                            details: Some(json!({
                                "observed_content_type": upstream_content_type,
                            })),
                            ..AuditEvent::default()
                        },
                    )
                    .await;
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({
                            "error": {
                                "message": "upstream content-type not allowed",
                                "type": "response_content_type_disallowed",
                            }
                        })),
                    )
                        .into_response();
                }
                // Tool has redaction patterns ⇒ buffer + apply
                // non-streaming. Tools that need streaming + redaction
                // compose with D-18 in-process scanners (LlamaFirewall)
                // — see m7-response-controls runbook.
                if rc_should_buffer(rc) {
                    return apply_buffered_response_controls(
                        rc,
                        &state.audit,
                        &tool_name,
                        upstream_host.clone(),
                        method.as_str(),
                        &request_path,
                        upstream_status,
                        upstream_content_type,
                        response_headers,
                        resp,
                        started,
                        auth_method_str,
                        agent_public_id.clone(),
                    )
                    .await;
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
                    auth_method: Some(auth_method_str.to_string()),
                    agent_public_id: agent_public_id.clone(),
                    ..AuditEvent::default()
                },
            )
            .await;
            // Stream the upstream body to the agent rather than buffering
            // (R-N6: ≤100ms first-byte added latency). T1.2 closes T1.1.
            // Wrap with the M7 size-cap adapter when configured.
            let body = match rc.as_ref().and_then(|c| c.streaming_size_cap()) {
                Some(cap) => {
                    let audit_for_truncate = state.audit.clone();
                    let tool_for_truncate = tool_name.clone();
                    let upstream_host_for_truncate = upstream_host.clone();
                    let method_for_truncate = method.as_str().to_string();
                    let path_for_truncate = request_path.clone();
                    let on_truncate = move |observed: u64| {
                        let event = AuditEvent {
                            ts_ms: now_ms(),
                            event_class: EventClass::Proxy,
                            event: "response_size_exceeded".to_string(),
                            tool: Some(tool_for_truncate),
                            upstream_host: upstream_host_for_truncate,
                            method: Some(method_for_truncate),
                            path: Some(path_for_truncate),
                            status: Some(upstream_status),
                            decision: Decision::Denied,
                            auth_method: Some(auth_method_str.to_string()),
                            details: Some(json!({
                                "observed_bytes": observed,
                                "cap_bytes": cap,
                                "flow": "streaming",
                            })),
                            ..AuditEvent::default()
                        };
                        if let Some(repo) = audit_for_truncate {
                            tokio::spawn(async move {
                                if let Err(e) = repo.record(&event).await {
                                    tracing::warn!(error = %e, "response_size_exceeded audit write failed");
                                }
                            });
                        }
                    };
                    let wrapped =
                        SizeCappedStream::new(resp.bytes_stream(), Some(cap), on_truncate);
                    Body::from_stream(wrapped)
                }
                None => Body::from_stream(resp.bytes_stream()),
            };
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
                    auth_method: Some(auth_method_str.to_string()),
                    agent_public_id: agent_public_id.clone(),
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
/// True when this tool's response controls require buffering the
/// full body before responding (M7 / SPEC §6.2 T7.2). Streaming
/// flows skip this path; redaction explicitly bypasses streaming
/// per SPEC ("only total-size cap applies to streaming").
fn rc_should_buffer(rc: &ResponseControls) -> bool {
    // Empty pattern list ⇒ no redaction work; stream as usual.
    // We discover this by attempting to compile a no-op against an
    // empty string — cheap and avoids exposing the field.
    rc_has_redaction(rc)
}

fn rc_has_redaction(rc: &ResponseControls) -> bool {
    // ResponseControls keeps `patterns` private. Use the public
    // surface: an empty body with no patterns produces an Allowed
    // outcome with no redaction records. If we run apply on a real
    // body we'd lose the bytes — but there's a cleaner check: the
    // streaming path uses size_cap + content_type only; redaction
    // is the differentiator. We expose this through the public API.
    rc.has_redaction_patterns()
}

#[allow(clippy::too_many_arguments)]
async fn apply_buffered_response_controls(
    rc: &ResponseControls,
    audit: &Option<AuditRepository>,
    tool_name: &str,
    upstream_host: Option<String>,
    method_str: &str,
    request_path: &str,
    upstream_status: u16,
    upstream_content_type: Option<String>,
    response_headers: HeaderMap,
    resp: reqwest::Response,
    started: Instant,
    auth_method_str: &str,
    agent_public_id: Option<String>,
) -> Response {
    let body_bytes = match resp.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => {
            audit_record(
                audit,
                AuditEvent {
                    ts_ms: now_ms(),
                    event_class: EventClass::Proxy,
                    event: "upstream_body_read_error".to_string(),
                    tool: Some(tool_name.to_string()),
                    upstream_host,
                    method: Some(method_str.to_string()),
                    path: Some(request_path.to_string()),
                    status: Some(502),
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    decision: Decision::Error,
                    auth_method: Some(auth_method_str.to_string()),
                    details: Some(json!({"error": e.to_string()})),
                    ..AuditEvent::default()
                },
            )
            .await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": {"message": "upstream body read failed", "type": "upstream_error"}})),
            )
                .into_response();
        }
    };
    match rc.apply_non_streaming(upstream_content_type.as_deref(), body_bytes) {
        ApplyOutcome::SizeExceeded { observed, cap } => {
            audit_record(
                audit,
                AuditEvent {
                    ts_ms: now_ms(),
                    event_class: EventClass::Proxy,
                    event: "response_size_exceeded".to_string(),
                    tool: Some(tool_name.to_string()),
                    upstream_host,
                    method: Some(method_str.to_string()),
                    path: Some(request_path.to_string()),
                    status: Some(502),
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    decision: Decision::Denied,
                    auth_method: Some(auth_method_str.to_string()),
                    details: Some(json!({
                        "observed_bytes": observed,
                        "cap_bytes": cap,
                        "flow": "non_streaming",
                    })),
                    ..AuditEvent::default()
                },
            )
            .await;
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": {"message": "response too large", "type": "response_size_exceeded"}
                })),
            )
                .into_response()
        }
        ApplyOutcome::ContentTypeDisallowed { observed } => {
            audit_record(
                audit,
                AuditEvent {
                    ts_ms: now_ms(),
                    event_class: EventClass::Proxy,
                    event: "response_content_type_disallowed".to_string(),
                    tool: Some(tool_name.to_string()),
                    upstream_host,
                    method: Some(method_str.to_string()),
                    path: Some(request_path.to_string()),
                    status: Some(502),
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    decision: Decision::Denied,
                    auth_method: Some(auth_method_str.to_string()),
                    details: Some(json!({"observed_content_type": observed})),
                    ..AuditEvent::default()
                },
            )
            .await;
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": {"message": "upstream content-type not allowed", "type": "response_content_type_disallowed"}
                })),
            )
                .into_response()
        }
        ApplyOutcome::Allowed { body, redactions } => {
            for rec in &redactions {
                audit_record(
                    audit,
                    AuditEvent {
                        ts_ms: now_ms(),
                        event_class: EventClass::Proxy,
                        event: "response_redaction".to_string(),
                        tool: Some(tool_name.to_string()),
                        upstream_host: upstream_host.clone(),
                        method: Some(method_str.to_string()),
                        path: Some(request_path.to_string()),
                        status: Some(upstream_status),
                        latency_ms: Some(started.elapsed().as_millis() as u64),
                        decision: Decision::Allowed,
                        auth_method: Some(auth_method_str.to_string()),
                        details: Some(json!({
                            "pattern_id": rec.pattern_id,
                            "matches": rec.matches,
                            "match_hash": rec.match_hash,
                        })),
                        ..AuditEvent::default()
                    },
                )
                .await;
            }
            // Final proxy_request audit row for the buffered flow.
            let decision = if upstream_status >= 500 {
                Decision::Error
            } else {
                Decision::Allowed
            };
            audit_record(
                audit,
                AuditEvent {
                    ts_ms: now_ms(),
                    event_class: EventClass::Proxy,
                    event: "proxy_request".to_string(),
                    tool: Some(tool_name.to_string()),
                    upstream_host,
                    method: Some(method_str.to_string()),
                    path: Some(request_path.to_string()),
                    status: Some(upstream_status),
                    latency_ms: Some(started.elapsed().as_millis() as u64),
                    decision,
                    auth_method: Some(auth_method_str.to_string()),
                    agent_public_id: agent_public_id.clone(),
                    ..AuditEvent::default()
                },
            )
            .await;
            let status_code =
                StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = status_code;
            *response.headers_mut() = response_headers;
            response
        }
    }
}

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

/// M9 / B1: emit a `security/authz_denied` audit row and return the
/// generic 403 wire response with the §4.7.9 envelope. Centralises the
/// deny-side audit + response so the proxy hot path stays readable.
/// `reason` is `"in_denylist"` or `"not_in_allowlist"` per `check_tool_acl`.
#[allow(clippy::too_many_arguments)]
async fn record_authz_denied(
    audit: &Option<AuditRepository>,
    tool_name: &str,
    method_str: &str,
    request_path: &str,
    started: Instant,
    auth_method_str: &str,
    agent_public_id: &Option<String>,
    reason: &'static str,
) -> Response {
    audit_record(
        audit,
        AuditEvent {
            ts_ms: now_ms(),
            event_class: EventClass::Security,
            event: "authz_denied".to_string(),
            tool: Some(tool_name.to_string()),
            method: Some(method_str.to_string()),
            path: Some(request_path.to_string()),
            status: Some(403),
            latency_ms: Some(started.elapsed().as_millis() as u64),
            decision: Decision::Denied,
            auth_method: Some(auth_method_str.to_string()),
            agent_public_id: agent_public_id.clone(),
            details: Some(json!({ "reason": reason })),
            ..AuditEvent::default()
        },
    )
    .await;
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": {
                "message": "tool access denied",
                "type": "authz_error",
                "code": "tool_not_allowed",
            }
        })),
    )
        .into_response()
}

/// M9 / B1 ACL check. Both lists optional. Allowlist `Some([...])`
/// → tool must be IN the list. Denylist `Some([...])` → tool must NOT
/// be in the list. If both are set and a tool appears in both, deny
/// wins (deny is always explicit). Both `None` → unrestricted.
fn check_tool_acl(
    identity: &crate::auth_v2::AgentIdentity,
    tool_name: &str,
) -> Result<(), &'static str> {
    if let Some(deny) = identity.tool_denylist.as_ref()
        && deny.iter().any(|t| t == tool_name)
    {
        return Err("in_denylist");
    }
    if let Some(allow) = identity.tool_allowlist.as_ref()
        && !allow.iter().any(|t| t == tool_name)
    {
        return Err("not_in_allowlist");
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_v2::AgentIdentity;

    fn ident(allow: Option<&[&str]>, deny: Option<&[&str]>) -> AgentIdentity {
        AgentIdentity {
            public_id: "test-pid".into(),
            name: "test".into(),
            tool_allowlist: allow.map(|s| s.iter().map(|t| t.to_string()).collect()),
            tool_denylist: deny.map(|s| s.iter().map(|t| t.to_string()).collect()),
        }
    }

    // TS-14 cross-coverage: the ACL gate is auth-method-agnostic. Identity
    // constructed by the mTLS authenticator (post-v2 / #67) flows through
    // the same `check_tool_acl` as bearer-derived identity.
    #[test]
    fn check_tool_acl_allows_when_no_lists() {
        assert!(check_tool_acl(&ident(None, None), "anything").is_ok());
    }

    #[test]
    fn check_tool_acl_enforces_allowlist_membership() {
        let id = ident(Some(&["github", "tavily"]), None);
        assert!(check_tool_acl(&id, "github").is_ok());
        assert_eq!(check_tool_acl(&id, "anthropic"), Err("not_in_allowlist"));
    }

    #[test]
    fn check_tool_acl_enforces_denylist_exclusion() {
        let id = ident(None, Some(&["dangerous"]));
        assert!(check_tool_acl(&id, "safe").is_ok());
        assert_eq!(check_tool_acl(&id, "dangerous"), Err("in_denylist"));
    }

    #[test]
    fn check_tool_acl_denylist_wins_when_both_overlap() {
        let id = ident(Some(&["x", "y"]), Some(&["x"]));
        assert_eq!(
            check_tool_acl(&id, "x"),
            Err("in_denylist"),
            "explicit deny must win over allowlist membership"
        );
        assert!(
            check_tool_acl(&id, "y").is_ok(),
            "non-overlapping allow still works"
        );
    }

    // M9 footgun guard: an allowlist of `Some(vec![])` is "no tools
    // permitted" — every request 403s. The runbook calls this out so
    // operators don't pass `--allowlist ""` expecting "unrestricted".
    #[test]
    fn check_tool_acl_empty_allowlist_denies_all() {
        let id = ident(Some(&[]), None);
        assert_eq!(check_tool_acl(&id, "anything"), Err("not_in_allowlist"));
        assert_eq!(check_tool_acl(&id, ""), Err("not_in_allowlist"));
    }

    // Symmetric edge: empty denylist is a no-op (no tool is in it).
    #[test]
    fn check_tool_acl_empty_denylist_is_noop() {
        let id = ident(None, Some(&[]));
        assert!(check_tool_acl(&id, "anything").is_ok());
    }
}
