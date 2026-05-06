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
use crate::config::{EgressMode, ToolConfig, ToolTimeouts};
use crate::registrations::{AuthSpec, Registration};
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

/// Phase E.6 — unified proxy target shape. Built from either an
/// in-memory `Registration` (catalog path) or a `ToolConfig`
/// (config.tools fallback). Owns its data so the hot path doesn't
/// hold borrows into the catalog `ArcSwap` snapshot or the config
/// snapshot across the upstream request.
struct ProxyTarget {
    name: String,
    upstream: String,
    body_limit_bytes: u64,
    timeouts: ToolTimeouts,
    egress: EgressMode,
    auth: ProxyAuth,
}

/// What the proxy needs to know about auth at injection time. Each
/// variant carries the audit label so `proxy_request` rows can record
/// the `auth_mode` used (see TS-151).
#[derive(Debug, Clone)]
enum ProxyAuth {
    /// `AuthSpec::None` — operator-stated authless. Strip incoming
    /// auth-shaped headers, inject nothing.
    None,
    /// Inject `header: value` where `value = resolved_creds[name]`.
    /// `audit_mode` distinguishes registration-sourced ("header") from
    /// config-sourced ("config") for the audit row.
    Header {
        header: String,
        audit_mode: &'static str,
    },
    /// Inject `Authorization: Bearer value` where `value =
    /// resolved_creds[name]`. Catalog-only — config.tools' Authorization
    /// shape goes through `Header { header: "Authorization", ... }`
    /// because the legacy resolver may have already prefixed the value.
    Bearer,
    /// OAuth (PKCE or device-code). The access token lives in the
    /// `oauth_sessions` cache, not in `resolved_creds`. Phase F.2 ships
    /// the AuthSpec variants + DB schema; **the proxy hot-path
    /// injection logic lands in Phase F.5**. Until F.5, this variant
    /// behaves like `None` on the wire (no header injection, upstream
    /// gets the agent's cred-stripped request) but reports the OAuth
    /// audit_mode so audit rows accurately reflect operator intent.
    Oauth {
        /// `"oauth_pkce"` or `"oauth_device_code"` per ADR-0005 D4.
        audit_mode: &'static str,
    },
}

impl ProxyAuth {
    fn audit_mode(&self) -> &'static str {
        match self {
            ProxyAuth::None => "none",
            ProxyAuth::Header { audit_mode, .. } => audit_mode,
            ProxyAuth::Bearer => "bearer",
            ProxyAuth::Oauth { audit_mode } => audit_mode,
        }
    }

    /// Header name (lowercased) that should be stripped from the
    /// agent's incoming request to prevent override of the configured
    /// credential. `None` means no specific stripping beyond the
    /// always-stripped `authorization` / `x-api-key` / `host`.
    fn strip_header_lower(&self) -> Option<String> {
        match self {
            ProxyAuth::None => None,
            ProxyAuth::Header { header, .. } => Some(header.to_lowercase()),
            ProxyAuth::Bearer => None, // "authorization" is always stripped
            ProxyAuth::Oauth { .. } => None, // F.5 will inject Authorization; always stripped
        }
    }
}

impl ProxyTarget {
    /// Build from a Phase E `Registration`. Translates `AuthSpec` →
    /// `ProxyAuth` so the build-upstream-request path is uniform across
    /// catalog and legacy sources.
    fn from_registration(r: &Registration) -> Self {
        let auth = match &r.auth {
            AuthSpec::None => ProxyAuth::None,
            AuthSpec::Header { header, .. } => ProxyAuth::Header {
                header: header.clone(),
                audit_mode: "header",
            },
            AuthSpec::Bearer { .. } => ProxyAuth::Bearer,
            AuthSpec::OauthPkce { .. } => ProxyAuth::Oauth {
                audit_mode: "oauth_pkce",
            },
            AuthSpec::OauthDeviceCode { .. } => ProxyAuth::Oauth {
                audit_mode: "oauth_device_code",
            },
        };
        Self {
            name: r.name.clone(),
            upstream: r.upstream.clone(),
            body_limit_bytes: r.body_limit_bytes,
            timeouts: r.timeouts,
            egress: r.egress,
            auth,
        }
    }

    /// Build from a legacy `ToolConfig`. Preserves the pre-Phase-E
    /// behavior: tools with `auth: { header, value: ... }` inject
    /// `header: <resolved>` (the resolved value may already include
    /// "Bearer " when the operator wrote a legacy "Bearer ${VAR}"
    /// string); tools with no `auth:` block inject nothing.
    fn from_tool_config(t: &ToolConfig) -> Self {
        let auth = match &t.auth {
            None => ProxyAuth::None,
            Some(a) => ProxyAuth::Header {
                header: a.header.clone(),
                audit_mode: "config",
            },
        };
        Self {
            name: t.name.clone(),
            upstream: t.upstream.clone(),
            body_limit_bytes: t.body_limit_bytes,
            timeouts: t.timeouts,
            egress: t.egress,
            auth,
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

    // Phase E.6: catalog lookup first; legacy `config.tools` fallback
    // for M0/M1 / M9 test paths that haven't wired registrations.
    let target = resolve_target(&state, &ctx.tool_name);
    let target = match target {
        Some(t) => t,
        None => return record_tool_not_found(&state.audit, &ctx).await,
    };

    let config = state.config.load();
    let upstream_host = url_host(&target.upstream);
    let upstream_url = format!("{}/{}", target.upstream.trim_end_matches('/'), path);
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = match read_request_body(req, target.body_limit_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return record_body_read_error(&state.audit, &ctx, upstream_host).await;
        }
    };

    let upstream_req = build_upstream_request(
        &state,
        &config,
        &target,
        method,
        &upstream_url,
        headers,
        body_bytes,
    );

    match upstream_req.send().await {
        Ok(resp) => {
            handle_upstream_response(state.clone(), &ctx, &target, upstream_host, resp).await
        }
        Err(e) => record_upstream_error(&state.audit, &ctx, &target, upstream_host, e).await,
    }
}

/// Phase E.6 lookup: try the in-memory catalog (registrations) first,
/// fall back to `config.tools`. Returns `None` only when the name is
/// in neither source — which is when `record_tool_not_found` should
/// fire.
fn resolve_target(state: &AppState, name: &str) -> Option<ProxyTarget> {
    // Catalog path. `lookup_active` already filters out `disabled=true`
    // rows so admin-disabled seed entries return None and proxy_handler
    // surfaces 404.
    let catalog = state.catalog.load();
    if let Some(r) = catalog.lookup_active(name) {
        return Some(ProxyTarget::from_registration(r));
    }
    drop(catalog);
    // Legacy fallback. `active_tools()` includes every tool whose
    // upstream is configured; credential-resolved filtering happens
    // implicitly via `resolved_creds.get(name)` at injection time.
    let config = state.config.load();
    config
        .active_tools()
        .into_iter()
        .find(|t| t.name == name)
        .map(ProxyTarget::from_tool_config)
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
/// the configured credential, and attach the body if present. Phase
/// E.6: source-agnostic — driven by `ProxyTarget` (built from either
/// a `Registration` or a legacy `ToolConfig`).
fn build_upstream_request(
    state: &AppState,
    config: &crate::config::AppConfig,
    target: &ProxyTarget,
    method: axum::http::Method,
    upstream_url: &str,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> reqwest::RequestBuilder {
    let client =
        state
            .client_pool
            .get_or_build_for(&target.name, target.timeouts, target.egress, config);
    let mut upstream_req = client.request(method, upstream_url);

    // Forward headers, stripping auth-related ones so the agent can't
    // override the configured credential. `host`/`authorization`/
    // `x-api-key` are always stripped (defense in depth — even when
    // `auth: none` we don't want the agent injecting their own bearer
    // and reaching the upstream as the proxy's principal). The
    // target's own auth header is also stripped when distinct.
    let extra_strip = target.auth.strip_header_lower();
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_lowercase();
        if lower == "host"
            || lower == "authorization"
            || lower == "x-api-key"
            || extra_strip.as_deref() == Some(&lower)
        {
            continue;
        }
        upstream_req = upstream_req.header(name, value);
    }

    // Inject configured credentials. Reads from the resolved-creds
    // snapshot (M5 / T5.1) — daemon resolves SecretRefs and
    // registration env vars once at startup, the proxy never touches
    // raw values on the hot path. AuthSpec::None deliberately skips
    // injection (Phase E.6 / TS-150).
    match &target.auth {
        ProxyAuth::None => {}
        ProxyAuth::Header { header, .. } => {
            let resolved = state.resolved_creds.load();
            if let Some(value) = resolved.get(&target.name) {
                upstream_req =
                    upstream_req.header(header, secrecy::ExposeSecret::expose_secret(value));
            }
            // Auth declared but no credential resolved → degraded
            // mode. Forward without injection; upstream typically
            // returns 401 and the response pipeline records the
            // proxy-side audit row.
        }
        ProxyAuth::Bearer => {
            let resolved = state.resolved_creds.load();
            if let Some(value) = resolved.get(&target.name) {
                let header_value =
                    format!("Bearer {}", secrecy::ExposeSecret::expose_secret(value));
                upstream_req = upstream_req.header("Authorization", header_value);
            }
        }
        ProxyAuth::Oauth { .. } => {
            // Phase F.5 will read access tokens from the oauth_sessions
            // cache and inject `Authorization: Bearer <access>`. Until
            // F.5 lands, OAuth registrations forward without injection;
            // the upstream will 401 and the audit row records
            // `auth_mode: oauth_pkce | oauth_device_code` so the
            // operator can see the gap. F.2 ships only the AuthSpec
            // variant + DB schema.
        }
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
    target: &ProxyTarget,
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
                target,
                upstream_host,
                upstream_status,
                upstream_content_type,
                response_headers,
                resp,
            )
            .await;
        }
    }

    record_proxy_request_success(
        &state.audit,
        ctx,
        target,
        upstream_host.clone(),
        upstream_status,
    )
    .await;

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
    target: &ProxyTarget,
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
    // Phase E.6 / TS-151 — record the upstream auth shape used. "none"
    // for AuthSpec::None (operator-stated authless), "bearer" /
    // "header" for the Phase E catalog path, "config" for the legacy
    // ToolConfig path, "config_absent" when ToolConfig had no auth
    // block at all.
    event.details = Some(json!({"auth_mode": target.auth.audit_mode()}));
    audit_record(audit, event).await;
}

/// Emit a `proxy/timeout` or `proxy/upstream_error` audit row + the
/// matching 504 / 502 wire response when the upstream call fails.
async fn record_upstream_error(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    target: &ProxyTarget,
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
    event.details = Some(json!({"auth_mode": target.auth.audit_mode()}));
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
    target: &ProxyTarget,
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
            record_response_content_type_disallowed(audit, ctx, upstream_host, Some(observed)).await
        }
        ApplyOutcome::Allowed { body, redactions } => {
            for rec in &redactions {
                record_response_redaction(audit, ctx, upstream_host.clone(), upstream_status, rec)
                    .await;
            }
            record_proxy_request_success(audit, ctx, target, upstream_host, upstream_status).await;
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
