use arc_swap::ArcSwap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router, extract::State, middleware, routing};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Instant;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::client_pool::ClientPool;
use crate::config::AppConfig;
use crate::proxy;
use crate::repo::AuditRepository;
use crate::response_controls::ResponseControls;
use crate::secret::{ResolvedCreds, resolve_tool_creds_sync_env_only};
use std::collections::HashMap;

pub struct AppState {
    pub config: Arc<ArcSwap<AppConfig>>,
    pub started_at: Instant,
    pub client_pool: ClientPool,
    /// Audit sink (T3.1). `None` for M0/M1 deployments without admin
    /// substrate; the proxy hot path then skips audit writes entirely
    /// rather than fail.
    pub audit: Option<AuditRepository>,
    /// Resolved credential map (M5 / T5.1). Populated at startup by
    /// the daemon (`secret::resolve_tool_creds`) or by the eager
    /// sync helper used in test paths
    /// (`secret::resolve_tool_creds_sync_env_only`). The proxy hot
    /// path reads from this map; tools whose credentials are absent
    /// are inactive (degraded per INF-4).
    pub resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
    /// Per-tool response controls (M7 / T7.2 / T7.3). Compiled once
    /// at AppState build; the proxy hot path looks up tool name and
    /// applies size-cap / content-type / redaction. Tools without a
    /// `response:` block are absent from the map and the proxy
    /// streams unchanged (M0..M6 behavior).
    pub response_controls: Arc<HashMap<String, ResponseControls>>,
}

fn compile_response_controls(cfg: &AppConfig) -> HashMap<String, ResponseControls> {
    let mut out = HashMap::new();
    for tool in &cfg.tools {
        let Some(rc_cfg) = &tool.response else {
            continue;
        };
        // parse_config_str validated the regex compile earlier; this
        // unwrap is structurally safe.
        match ResponseControls::compile(rc_cfg) {
            Ok(rc) => {
                out.insert(tool.name.clone(), rc);
            }
            Err(e) => {
                tracing::error!(
                    tool = %tool.name,
                    error = %e,
                    "response_controls compile failed at AppState build (config validation should have caught this)"
                );
            }
        }
    }
    out
}

pub fn build_app(config: AppConfig) -> Router {
    build_app_with_shared_config(Arc::new(ArcSwap::from_pointee(config)))
}

/// Build the agent router using a shared config snapshot. M2's daemon
/// runtime calls this so the agent listener and the AdminService observe
/// the same `ArcSwap<AppConfig>` (single source of truth for hot reload).
pub fn build_app_with_shared_config(config: Arc<ArcSwap<AppConfig>>) -> Router {
    build_app_with_audit(config, None)
}

/// Build the agent router with an optional audit sink. M3 calls this so
/// the proxy hot path emits one audit row per request. Eager-resolves
/// `tool.auth.value` SecretRefs synchronously (env + legacy paths only) —
/// daemon callers that need sealed/Vault/AWS go through
/// `build_app_with_audit_and_creds`.
pub fn build_app_with_audit(
    config: Arc<ArcSwap<AppConfig>>,
    audit: Option<AuditRepository>,
) -> Router {
    let snapshot = config.load();
    let resolved = resolve_tool_creds_sync_env_only(&snapshot);
    drop(snapshot);
    build_app_with_audit_and_creds(config, audit, Arc::new(ArcSwap::from_pointee(resolved)))
}

/// Full-power constructor used by the daemon: caller supplies an
/// already-resolved credentials map (typically built via the async
/// `secret::resolve_tool_creds` so sealed/Vault/AWS paths work).
pub fn build_app_with_audit_and_creds(
    config: Arc<ArcSwap<AppConfig>>,
    audit: Option<AuditRepository>,
    resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
) -> Router {
    let snapshot = config.load();
    let response_controls = Arc::new(compile_response_controls(&snapshot));
    drop(snapshot);
    let state = Arc::new(AppState {
        config,
        started_at: Instant::now(),
        client_pool: ClientPool::new(),
        audit,
        resolved_creds,
        response_controls,
    });

    Router::new()
        // k8s-style health endpoints (INF-3 / Q-18). Unauthenticated by
        // design — orchestrators should not need credentials to probe the
        // process. /health is preserved as an alias to /livez for
        // backward compatibility with M0 deployments.
        .route("/livez", routing::get(livez_handler))
        .route("/health", routing::get(livez_handler))
        .route("/readyz", routing::get(readyz_handler))
        .route("/version", routing::get(version_handler))
        .route("/tools", routing::get(tools_handler))
        .route(
            "/api/{tool_name}/{*path}",
            routing::any(proxy::proxy_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Liveness: process is up. Returns 200 unless the process is so broken it
/// cannot serve a fixed response. INF-3.
async fn livez_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "status": "live",
        "uptime_seconds": state.started_at.elapsed().as_secs(),
    }))
}

/// Readiness: process is ready to serve traffic. Returns 200 only when all
/// tools that declare an `auth` block have a resolved credential
/// (non-empty value). Tools without auth declarations are always ready.
/// In M2, this also checks DB reachability.
///
/// "Required backend" semantics (per INF-3 / Q-18 / A-4): in M1, all tools
/// are considered required. M2 introduces per-tool `on_secret_failure:
/// degraded` to opt out of the readiness check.
async fn readyz_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config.load();
    let resolved = state.resolved_creds.load();
    let unconfigured: Vec<&str> = config
        .tools
        .iter()
        .filter(|t| match &t.auth {
            Some(_) => !resolved.contains_key(&t.name),
            None => false,
        })
        .map(|t| t.name.as_str())
        .collect();

    if !unconfigured.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "reason": "tool_credentials_unresolved",
                "tools": unconfigured,
            })),
        )
            .into_response();
    }

    Json(json!({
        "status": "ready",
        "uptime_seconds": state.started_at.elapsed().as_secs(),
    }))
    .into_response()
}

/// Build metadata. Unauthenticated; useful for incident response and
/// debugging. INF-3.
async fn version_handler() -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
    }))
}

async fn tools_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let config = state.config.load();
    let resolved = state.resolved_creds.load();
    let tools: Vec<Value> = config
        .active_tools_against(&resolved)
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "type": "api",
                "path": format!("/api/{}", t.name),
                "description": t.description,
            })
        })
        .collect();

    Json(json!({ "tools": tools }))
}
