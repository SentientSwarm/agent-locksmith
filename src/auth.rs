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
use crate::auth_v2::AuthError;
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

    // M9 / B1: per-agent bearer authentication when the admin substrate
    // is enabled (BearerAuthenticator wired by daemon.rs). On success
    // we stamp `AuthenticatedAs::Bearer` AND the resolved `AgentIdentity`
    // into request extensions so `proxy::proxy_handler` can enforce
    // tool ACL and emit `agent_public_id` audit rows.
    if let Some(authn) = state.bearer_authenticator.as_ref() {
        let header = match req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
        {
            Some(h) => h.to_string(),
            None => return auth_error_response(&AuthError::MissingCredential),
        };
        return match authn.authenticate_bearer(&header).await {
            Ok(identity) => {
                req.extensions_mut().insert(AuthenticatedAs::Bearer);
                req.extensions_mut().insert(identity);
                next.run(req).await
            }
            Err(e) => auth_error_response(&e),
        };
    }

    // M0/M1 shared-bearer fallback. Preserves pre-v2 behavior for
    // deployments that haven't enabled the admin substrate
    // (`listen.admin_socket` + `database.path`). When the admin
    // substrate IS enabled, the branch above handles the request and
    // this fallback is unreachable.
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

/// Render an `AuthError` as a uniform §4.7.9 error envelope. Maps the
/// variant's `status()` (401 / 429 / 500) and `code()` into the wire
/// JSON; for `RateLimited`, also sets the `Retry-After` header.
pub(crate) fn auth_error_response(err: &AuthError) -> Response {
    let status = StatusCode::from_u16(err.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = json!({
        "error": {
            "message": err.to_string(),
            "type": "auth_error",
            "code": err.code(),
        }
    });
    let mut resp = (status, Json(body)).into_response();
    if let AuthError::RateLimited { retry_after } = err
        && let Ok(v) = axum::http::HeaderValue::from_str(&retry_after.as_secs().to_string())
    {
        resp.headers_mut()
            .insert(axum::http::header::RETRY_AFTER, v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::time::Duration;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn auth_error_response_missing_credential_is_401() {
        let resp = auth_error_response(&AuthError::MissingCredential);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["type"], "auth_error");
        assert_eq!(body["error"]["code"], "invalid_credential");
    }

    #[tokio::test]
    async fn auth_error_response_expired_is_401_with_expired_code() {
        let resp = auth_error_response(&AuthError::Expired);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "expired");
    }

    // TS-16: forward-compat — RateLimited renders 429 with Retry-After
    // header. No current authenticator emits this, but the M9 helper
    // honors the contract so future RateLimiter (WEM-235) work doesn't
    // need to retouch the wire shape.
    #[tokio::test]
    async fn ts16_rate_limited_renders_429_with_retry_after_header() {
        let resp = auth_error_response(&AuthError::RateLimited {
            retry_after: Duration::from_secs(7),
        });
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok());
        assert_eq!(retry_after, Some("7"));
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn auth_error_response_backend_is_500_with_generic_message() {
        let resp = auth_error_response(&AuthError::Backend("internals".into()));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "backend_error");
    }
}
