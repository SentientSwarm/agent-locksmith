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

use crate::agent_listener::PeerCertDer;
use crate::app::AppState;
use crate::config::AuthMode;

/// Recorded on the request extension to tell downstream code (proxy
/// audit emit) which transport authenticated this request. Drives the
/// `auth_method` audit column (T6.10).
#[derive(Clone, Debug)]
pub enum AuthenticatedAs {
    /// M0/M1 shared bearer or M2 per-agent bearer.
    Bearer,
    /// M6 client certificate.
    Mtls,
}

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    // Skip auth for unauthenticated probes / metadata endpoints (INF-3).
    // /health is preserved as an alias to /livez for backward compat with
    // M0 deployments.
    let path = req.uri().path();
    if matches!(path, "/livez" | "/readyz" | "/version" | "/health") {
        return next.run(req).await;
    }

    let auth_mode = state.config.load().listen.auth_mode;

    // mTLS branches (post-v2 / #67). Under `Mtls` we require a peer
    // cert; under `Both` we try mTLS first and fall back to bearer.
    if matches!(auth_mode, AuthMode::Mtls | AuthMode::Both) {
        let peer = req.extensions().get::<PeerCertDer>().cloned();
        let has_cert = peer.as_ref().is_some_and(|p| p.0.is_some());
        if has_cert {
            let cert = peer.unwrap().0.unwrap();
            let Some(authn) = state.mtls_authenticator.clone() else {
                tracing::error!(
                    "auth_mode={:?} but no mtls_authenticator wired in AppState",
                    auth_mode
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": {"message": "mtls_misconfigured", "type": "auth_error"}})),
                )
                    .into_response();
            };
            return match authn.authenticate_cert(&cert).await {
                Ok(identity) => {
                    req.extensions_mut().insert(AuthenticatedAs::Mtls);
                    req.extensions_mut().insert(identity);
                    next.run(req).await
                }
                Err(_) => (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": {"message": "Unauthorized", "type": "auth_error"}})),
                )
                    .into_response(),
            };
        }
        if matches!(auth_mode, AuthMode::Mtls) {
            // Strict mode requires a client cert.
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": {
                        "message": "client certificate required",
                        "type": "auth_error",
                    }
                })),
            )
                .into_response();
        }
        // Both: fall through to bearer path.
    }

    // M0 shared-bearer path. Per-agent bearer auth on the proxy hot
    // path is a separate carry-over (audit_proxy_test.rs notes this);
    // M2's admin substrate uses BearerAuthenticator on the admin UDS.
    let config = state.config.load();
    let auth_config = match &config.inbound_auth {
        Some(auth) if auth.mode == "bearer" => auth,
        _ => {
            req.extensions_mut().insert(AuthenticatedAs::Bearer);
            return next.run(req).await;
        }
    };
    let expected_token = match &auth_config.token {
        Some(t) => t,
        None => {
            req.extensions_mut().insert(AuthenticatedAs::Bearer);
            return next.run(req).await;
        }
    };
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    let provided_token = auth_header.and_then(|h| h.strip_prefix("Bearer "));
    match provided_token {
        Some(token) if token == expected_token.expose_secret() => {
            req.extensions_mut().insert(AuthenticatedAs::Bearer);
            next.run(req).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"message": "Unauthorized", "type": "auth_error"}})),
        )
            .into_response(),
    }
}
