use arc_swap::ArcSwap;
use axum::{Json, Router, extract::State, middleware, routing};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Instant;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::config::AppConfig;
use crate::proxy;

pub struct AppState {
    pub config: ArcSwap<AppConfig>,
    pub started_at: Instant,
}

pub fn build_app(config: AppConfig) -> Router {
    let state = Arc::new(AppState {
        config: ArcSwap::from_pointee(config),
        started_at: Instant::now(),
    });

    Router::new()
        .route("/health", routing::get(health_handler))
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

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let config = state.config.load();
    let tool_names: Vec<String> = config
        .active_tools()
        .iter()
        .map(|t| t.name.clone())
        .collect();

    Json(json!({
        "status": "ok",
        "uptime_seconds": state.started_at.elapsed().as_secs(),
        "tools": tool_names,
        "version": env!("CARGO_PKG_VERSION"),
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
