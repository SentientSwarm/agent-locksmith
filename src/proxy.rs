use axum::{
    Json,
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

use crate::app::AppState;
use crate::config::ToolConfig;
use crate::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};
use crate::response_controls::{ApplyOutcome, ResponseControls, SizeCappedStream};

/// Per-request context snapshot. Built once at the top of `proxy_handler`
/// and threaded through every audit-emitting helper so each call site
/// shares one consistent set of identity / timing / metadata fields.
/// Replaces the pre-M9 pattern of cloning these strings 3-5 times per
/// request inline.
struct RequestCtx {
    tool_name: String,
    request_path: String,
    /// `Method::as_str()` snapshot — kept as `String` so it survives
    /// being moved into audit events without re-borrowing the request.
    method: String,
    /// `"bearer"` or `"mtls"`, derived from `AuthenticatedAs` in
    /// request extensions.
    auth_method: &'static str,
    /// Stamped only when the bearer or mTLS path resolved an
    /// `AgentIdentity` into request extensions (M0/M1 deployments
    /// without admin substrate leave this `None`).
    agent_public_id: Option<String>,
    started: Instant,
}

impl RequestCtx {
    /// Snapshot the request metadata. Reads `AuthenticatedAs` and
    /// `AgentIdentity` from request extensions (stamped by the
    /// `auth::auth_middleware`).
    fn snapshot(req: &Request<Body>, tool_name: String) -> Self {
        let started = Instant::now();
        let request_path = req.uri().path().to_string();
        let method = req.method().as_str().to_string();
        let auth_method = match req.extensions().get::<crate::auth::AuthenticatedAs>() {
            Some(crate::auth::AuthenticatedAs::Mtls) => "mtls",
            _ => "bearer",
        };
        let agent_public_id = req
            .extensions()
            .get::<crate::auth_v2::AgentIdentity>()
            .map(|id| id.public_id.clone());
        Self {
            tool_name,
            request_path,
            method,
            auth_method,
            agent_public_id,
            started,
        }
    }

    fn latency_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// An `AuditEvent` with the per-request metadata fields populated.
    /// Caller fills in `event_class`, `event`, `status`, `decision`,
    /// `details`, and `upstream_host`.
    fn audit_event_base(&self) -> AuditEvent {
        AuditEvent {
            ts_ms: now_ms(),
            tool: Some(self.tool_name.clone()),
            method: Some(self.method.clone()),
            path: Some(self.request_path.clone()),
            latency_ms: Some(self.latency_ms()),
            auth_method: Some(self.auth_method.to_string()),
            agent_public_id: self.agent_public_id.clone(),
            ..AuditEvent::default()
        }
    }
}

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path((tool_name, path)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    let ctx = RequestCtx::snapshot(&req, tool_name);

    // M9 ACL gate. When the request carries an AgentIdentity (per-agent
    // bearer or mTLS), enforce the agent's tool_allowlist /
    // tool_denylist before reaching the tool resolver. Identity-less
    // requests reach this code only in M0/M1 deployments without admin
    // substrate (preserved for back-compat).
    if let Some(identity) = req.extensions().get::<crate::auth_v2::AgentIdentity>()
        && let Err(reason) = identity.allows_tool(&ctx.tool_name)
    {
        return record_authz_denied(&state.audit, &ctx, reason).await;
    }

    let config = state.config.load();
    let tool = match config
        .active_tools()
        .into_iter()
        .find(|t| t.name == ctx.tool_name)
    {
        Some(t) => t,
        None => return record_tool_not_found(&state.audit, &ctx).await,
    };

    let upstream_host = url_host(&tool.upstream);
    let upstream_url = format!("{}/{}", tool.upstream.trim_end_matches('/'), path);
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = match read_request_body(req, tool.body_limit_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return record_body_read_error(&state.audit, &ctx, upstream_host).await;
        }
    };

    let upstream_req = build_upstream_request(
        &state,
        &config,
        tool,
        method,
        &upstream_url,
        headers,
        body_bytes,
    );

    match upstream_req.send().await {
        Ok(resp) => handle_upstream_response(state.clone(), &ctx, upstream_host, resp).await,
        Err(e) => record_upstream_error(&state.audit, &ctx, upstream_host, e).await,
    }
}

/// Read the request body up to the tool's `body_limit_bytes`. On error
/// returns `()` — the caller emits the audit row with `RequestCtx`
/// fields it already has.
async fn read_request_body(req: Request<Body>, body_limit: u64) -> Result<Bytes, ()> {
    let limit = usize::try_from(body_limit).unwrap_or(usize::MAX);
    axum::body::to_bytes(req.into_body(), limit)
        .await
        .map_err(|_| ())
}

/// Forward request headers (with auth-related headers stripped) plus
/// the configured tool credential, and attach the body if present.
fn build_upstream_request(
    state: &AppState,
    config: &crate::config::AppConfig,
    tool: &ToolConfig,
    method: axum::http::Method,
    upstream_url: &str,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> reqwest::RequestBuilder {
    let client = state.client_pool.get_or_build(tool, config);
    let mut upstream_req = client.request(method, upstream_url);

    // Forward headers, stripping auth-related ones so the agent can't
    // override the configured credential.
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
        }
        // Tool declared auth but no credential resolved → degraded
        // mode. Fall through without injection; upstream returns 401
        // and we record the proxy-side audit row from the response
        // pipeline.
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes);
    }
    upstream_req
}

/// Top-level dispatch for the upstream's response: snapshot headers,
/// apply M7 response-controls (size cap / content-type allowlist /
/// redaction), emit the success audit row, and stream the body to the
/// agent. Any Stage-specific deny path emits its own audit row before
/// returning.
async fn handle_upstream_response(
    state: Arc<AppState>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    resp: reqwest::Response,
) -> Response {
    let upstream_status = resp.status().as_u16();
    let status = StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::BAD_GATEWAY);
    // Snapshot upstream Content-Type before consuming the response —
    // needed for response-controls dispatch and for the response we
    // hand to the agent.
    let upstream_content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let response_headers = forward_response_headers(resp.headers());

    // M7 / T7.2-T7.4: per-tool response controls.
    let rc = state.response_controls.get(&ctx.tool_name).cloned();
    if let Some(rc) = rc.as_ref() {
        // Content-type allowlist (T7.2 streaming pre-check).
        if !rc.streaming_content_type_allowed(upstream_content_type.as_deref()) {
            return record_response_content_type_disallowed(
                &state.audit,
                ctx,
                upstream_host,
                upstream_content_type,
            )
            .await;
        }
        // Tool has redaction patterns ⇒ buffer + apply non-streaming.
        // Tools that need streaming + redaction compose with D-18
        // in-process scanners (LlamaFirewall) — see m7-response-controls
        // runbook.
        if rc_should_buffer(rc) {
            return apply_buffered_response_controls(
                rc,
                &state.audit,
                ctx,
                upstream_host,
                upstream_status,
                upstream_content_type,
                response_headers,
                resp,
            )
            .await;
        }
    }

    record_proxy_request_success(&state.audit, ctx, upstream_host.clone(), upstream_status).await;

    // Stream the upstream body to the agent rather than buffering
    // (R-N6: ≤100ms first-byte added latency). T1.2 closes T1.1.
    // Wrap with the M7 size-cap adapter when configured.
    let body = match rc.as_ref().and_then(|c| c.streaming_size_cap()) {
        Some(cap) => {
            let on_truncate = build_streaming_truncate_callback(
                state.audit.clone(),
                ctx,
                upstream_host,
                upstream_status,
                cap,
            );
            let wrapped = SizeCappedStream::new(resp.bytes_stream(), Some(cap), on_truncate);
            Body::from_stream(wrapped)
        }
        None => Body::from_stream(resp.bytes_stream()),
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    response
}

/// Strip hop-by-hop headers (the body is rebuilt as an axum stream
/// downstream, so axum/hyper sets these afresh).
fn forward_response_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in upstream {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "transfer-encoding"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "upgrade"
                | "te"
                | "trailer"
        ) {
            continue;
        }
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            out.insert(name.clone(), v);
        }
    }
    out
}

/// Build the `on_truncate` callback for `SizeCappedStream`. Spawned as
/// a tokio task on truncation so the audit write doesn't stall the
/// stream backpressure (INF-26). Captured fields are owned snapshots
/// of the request context.
fn build_streaming_truncate_callback(
    audit: Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    upstream_status: u16,
    cap: u64,
) -> impl FnMut(u64) + Send + 'static {
    let tool = ctx.tool_name.clone();
    let method = ctx.method.clone();
    let path = ctx.request_path.clone();
    let auth_method = ctx.auth_method;
    let agent_public_id = ctx.agent_public_id.clone();
    move |observed: u64| {
        let event = AuditEvent {
            ts_ms: now_ms(),
            event_class: EventClass::Proxy,
            event: "response_size_exceeded".to_string(),
            tool: Some(tool.clone()),
            upstream_host: upstream_host.clone(),
            method: Some(method.clone()),
            path: Some(path.clone()),
            status: Some(upstream_status),
            decision: Decision::Denied,
            auth_method: Some(auth_method.to_string()),
            agent_public_id: agent_public_id.clone(),
            details: Some(json!({
                "observed_bytes": observed,
                "cap_bytes": cap,
                "flow": "streaming",
            })),
            ..AuditEvent::default()
        };
        if let Some(repo) = audit.clone() {
            tokio::spawn(async move {
                if let Err(e) = repo.record(&event).await {
                    tracing::warn!(error = %e, "response_size_exceeded audit write failed");
                }
            });
        }
    }
}

// ─── Audit-emitting helpers (one per response shape) ──────────────────
//
// Each helper centralises the "emit an audit row + return the wire
// response" pattern for a specific deny / error shape, so the
// orchestrator (`proxy_handler` / `handle_upstream_response`) reads as
// pure flow control.

/// M9 / B1: emit a `security/authz_denied` audit row and return the
/// generic 403 wire response with the §4.7.9 envelope. `reason` is
/// `"in_denylist"` or `"not_in_allowlist"` per `AgentIdentity::allows_tool`.
async fn record_authz_denied(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    reason: &'static str,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Security;
    event.event = "authz_denied".to_string();
    event.status = Some(403);
    event.decision = Decision::Denied;
    event.details = Some(json!({ "reason": reason }));
    audit_record(audit, event).await;
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

/// Emit a `proxy/tool_not_found` audit row + 404 wire response when
/// the requested tool name does not match any active tool.
async fn record_tool_not_found(audit: &Option<AuditRepository>, ctx: &RequestCtx) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "tool_not_found".to_string();
    event.status = Some(404);
    event.decision = Decision::Denied;
    audit_record(audit, event).await;
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": {
                "message": format!("Unknown tool: {}", ctx.tool_name),
                "type": "not_found",
            }
        })),
    )
        .into_response()
}

/// Emit a `proxy/request_body_read_error` audit row + 400 wire response
/// when reading the agent's request body fails (typically the
/// per-tool body-size cap was exceeded).
async fn record_body_read_error(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "request_body_read_error".to_string();
    event.status = Some(400);
    event.decision = Decision::Error;
    event.upstream_host = upstream_host;
    audit_record(audit, event).await;
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": {"message": "Failed to read request body", "type": "bad_request"}})),
    )
        .into_response()
}

/// Emit a `proxy/response_content_type_disallowed` audit row + 502
/// wire response when the upstream's Content-Type isn't in the M7
/// allowlist.
async fn record_response_content_type_disallowed(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    upstream_content_type: Option<String>,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "response_content_type_disallowed".to_string();
    event.status = Some(502);
    event.decision = Decision::Denied;
    event.upstream_host = upstream_host;
    event.details = Some(json!({
        "observed_content_type": upstream_content_type,
    }));
    audit_record(audit, event).await;
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "error": {
                "message": "upstream content-type not allowed",
                "type": "response_content_type_disallowed",
            }
        })),
    )
        .into_response()
}

/// Emit the streaming-success `proxy/proxy_request` audit row.
async fn record_proxy_request_success(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    upstream_status: u16,
) {
    let decision = if upstream_status >= 500 {
        Decision::Error
    } else {
        Decision::Allowed
    };
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "proxy_request".to_string();
    event.status = Some(upstream_status);
    event.decision = decision;
    event.upstream_host = upstream_host;
    audit_record(audit, event).await;
}

/// Emit a `proxy/timeout` or `proxy/upstream_error` audit row + the
/// matching 504 / 502 wire response when the upstream call fails.
async fn record_upstream_error(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    e: reqwest::Error,
) -> Response {
    let (status, kind, message) = if e.is_timeout() {
        (StatusCode::GATEWAY_TIMEOUT, "timeout", "Upstream timeout")
    } else {
        (StatusCode::BAD_GATEWAY, "upstream_error", "Upstream error")
    };
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = kind.to_string();
    event.status = Some(status.as_u16());
    event.decision = Decision::Error;
    event.upstream_host = upstream_host;
    audit_record(audit, event).await;
    (
        status,
        Json(json!({"error": {"message": message, "type": kind}})),
    )
        .into_response()
}

/// True when this tool's response controls require buffering the
/// full body before responding (M7 / SPEC §6.2 T7.2). Streaming flows
/// skip this path; redaction explicitly bypasses streaming per SPEC
/// ("only total-size cap applies to streaming").
fn rc_should_buffer(rc: &ResponseControls) -> bool {
    rc.has_redaction_patterns()
}

/// M7 buffered response pipeline (size cap + content-type + redaction).
/// Reached only when `rc_should_buffer(rc)` is true (i.e. there are
/// redaction patterns to apply).
#[allow(clippy::too_many_arguments)]
async fn apply_buffered_response_controls(
    rc: &ResponseControls,
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    upstream_status: u16,
    upstream_content_type: Option<String>,
    response_headers: HeaderMap,
    resp: reqwest::Response,
) -> Response {
    let body_bytes = match resp.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => return record_upstream_body_read_error(audit, ctx, upstream_host, e).await,
    };
    match rc.apply_non_streaming(upstream_content_type.as_deref(), body_bytes) {
        ApplyOutcome::SizeExceeded { observed, cap } => {
            record_response_size_exceeded_buffered(audit, ctx, upstream_host, observed, cap).await
        }
        ApplyOutcome::ContentTypeDisallowed { observed } => {
            record_response_content_type_disallowed(audit, ctx, upstream_host, Some(observed))
                .await
        }
        ApplyOutcome::Allowed { body, redactions } => {
            for rec in &redactions {
                record_response_redaction(audit, ctx, upstream_host.clone(), upstream_status, rec)
                    .await;
            }
            record_proxy_request_success(audit, ctx, upstream_host, upstream_status).await;
            let status_code =
                StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = status_code;
            *response.headers_mut() = response_headers;
            response
        }
    }
}

async fn record_upstream_body_read_error(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    e: reqwest::Error,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "upstream_body_read_error".to_string();
    event.status = Some(502);
    event.decision = Decision::Error;
    event.upstream_host = upstream_host;
    event.details = Some(json!({"error": e.to_string()}));
    audit_record(audit, event).await;
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": {"message": "upstream body read failed", "type": "upstream_error"}})),
    )
        .into_response()
}

async fn record_response_size_exceeded_buffered(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    observed: usize,
    cap: u64,
) -> Response {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "response_size_exceeded".to_string();
    event.status = Some(502);
    event.decision = Decision::Denied;
    event.upstream_host = upstream_host;
    event.details = Some(json!({
        "observed_bytes": observed,
        "cap_bytes": cap,
        "flow": "non_streaming",
    }));
    audit_record(audit, event).await;
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "error": {"message": "response too large", "type": "response_size_exceeded"}
        })),
    )
        .into_response()
}

async fn record_response_redaction(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    upstream_host: Option<String>,
    upstream_status: u16,
    rec: &crate::response_controls::RedactionRecord,
) {
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Proxy;
    event.event = "response_redaction".to_string();
    event.status = Some(upstream_status);
    event.decision = Decision::Allowed;
    event.upstream_host = upstream_host;
    event.details = Some(json!({
        "pattern_id": rec.pattern_id,
        "matches": rec.matches,
        "match_hash": rec.match_hash,
    }));
    audit_record(audit, event).await;
}

/// Best-effort audit write. Errors are logged and swallowed — audit
/// must never block proxy traffic (INF-26).
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
