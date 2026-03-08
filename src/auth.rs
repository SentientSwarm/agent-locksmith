use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::Arc;

use crate::app::AppState;

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    // Skip auth for /health (load balancer probes)
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }

    let config = state.config.load();
    let auth_config = match &config.inbound_auth {
        Some(auth) if auth.mode == "bearer" => auth,
        _ => return next.run(req).await,
    };

    let expected_token = match &auth_config.token {
        Some(t) => t,
        None => return next.run(req).await,
    };

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let provided_token = auth_header.and_then(|h| h.strip_prefix("Bearer "));

    match provided_token {
        Some(token) if token == expected_token.expose_secret() => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"message": "Unauthorized", "type": "auth_error"}})),
        )
            .into_response(),
    }
}
