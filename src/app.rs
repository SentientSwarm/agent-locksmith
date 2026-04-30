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

pub struct AppState {
    pub config: Arc<ArcSwap<AppConfig>>,
    pub started_at: Instant,
    pub client_pool: ClientPool,
}

pub fn build_app(config: AppConfig) -> Router {
    build_app_with_shared_config(Arc::new(ArcSwap::from_pointee(config)))
}

/// Build the agent router using a shared config snapshot. M2's daemon
/// runtime calls this so the agent listener and the AdminService observe
/// the same `ArcSwap<AppConfig>` (single source of truth for hot reload).
pub fn build_app_with_shared_config(config: Arc<ArcSwap<AppConfig>>) -> Router {
    let state = Arc::new(AppState {
        config,
        started_at: Instant::now(),
        client_pool: ClientPool::new(),
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
    let unconfigured: Vec<&str> = config
        .tools
        .iter()
        .filter(|t| match &t.auth {
            Some(auth) => secrecy::ExposeSecret::expose_secret(&auth.value).is_empty(),
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
    let tools: Vec<Value> = config
        .active_tools()
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
