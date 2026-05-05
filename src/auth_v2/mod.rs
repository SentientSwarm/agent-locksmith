//! Per-agent and per-operator authentication for M2.
//!
//! M0's `src/auth.rs` ships a single static-token middleware
//! (`auth_middleware`) — a process-wide bearer that gates the agent
//! listener. M2 replaces it with structured per-agent identity and per-
//! operator credentials.
//!
//! Module layout:
//! - `agent`: `AgentAuthenticator` trait + bearer impl. C-6 (§4.2.8).
//! - `operator`: `OperatorAuthenticator` for admin endpoints. C-7
//!   (§4.2.9), lands in T2.10.
//!
//! `AuthError` is shared so the listener middleware can dispatch on a
//! single error type regardless of which authenticator produced it.

pub mod agent;
pub mod operator;

pub use agent::{AgentAuthenticator, AgentIdentity, BearerAuthenticator};
pub use operator::{OperatorAuthenticator, OperatorIdentity};

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::time::Duration;

/// Authentication errors. Each variant maps to a specific HTTP response
/// shape per the §4.7.9 error envelope.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// `Authorization` header missing entirely. 401.
    #[error("missing credential")]
    MissingCredential,
    /// Credential is malformed, the public_id doesn't exist, the secret
    /// doesn't verify, or any other "shape says no" failure. The wire
    /// shape is deliberately uniform — we do NOT distinguish "no such
    /// agent" from "wrong secret" to attackers (per §4.7.9 / Q-8). 401.
    #[error("invalid credential")]
    InvalidCredential,
    /// Agent record exists but is revoked. 401.
    #[error("revoked")]
    Revoked,
    /// Agent record exists but `expires_at` is in the past. 401.
    #[error("expired")]
    Expired,
    /// Per-IP or per-target rate limit hit. 429 with `Retry-After`.
    #[error("rate limited")]
    RateLimited { retry_after: Duration },
    /// Underlying repository / IO failure. 500. The inner string is for
    /// log/tracing only — the `Display` impl renders a generic
    /// `"internal error"` message so callers that route the variant
    /// through `auth_error_response` (which uses `to_string()` for the
    /// wire body) do NOT leak operational discriminators (sqlx errors,
    /// file paths, parse positions). To inspect the inner string,
    /// match on the variant directly.
    #[error("internal error")]
    Backend(String),
    /// mTLS-specific misconfiguration on the daemon side (e.g. auth_mode
    /// requires mTLS but the authenticator wasn't wired). 500. Like
    /// `Backend`, the wire renders a generic message; the discriminating
    /// detail is logged at `tracing::error!` only.
    #[error("internal error")]
    MtlsMisconfigured,
}

impl AuthError {
    /// HTTP status code for the wire response.
    pub fn status(&self) -> u16 {
        match self {
            AuthError::MissingCredential
            | AuthError::InvalidCredential
            | AuthError::Revoked
            | AuthError::Expired => 401,
            AuthError::RateLimited { .. } => 429,
            AuthError::Backend(_) | AuthError::MtlsMisconfigured => 500,
        }
    }

    /// Wire `code` per §4.7.9 — the same code value that audit events
    /// use, so operators can correlate logs and audit by grepping.
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::MissingCredential | AuthError::InvalidCredential => "invalid_credential",
            AuthError::Revoked => "revoked",
            AuthError::Expired => "expired",
            AuthError::RateLimited { .. } => "rate_limited",
            AuthError::Backend(_) => "backend_error",
            AuthError::MtlsMisconfigured => "internal_error",
        }
    }
}

/// Render an `AuthError` as a uniform §4.7.9 error envelope. Maps the
/// variant's `status()` and `code()` into the wire JSON; for
/// `RateLimited`, also sets the `Retry-After` header.
///
/// Co-located with `AuthError` so all "how does this variant render to
/// the wire" logic lives in one file. Used by both the bearer and mTLS
/// branches of `auth::auth_middleware`.
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

    // Backend renders 500 with `code: backend_error` (operator-distinguishable
    // from MtlsMisconfigured) but a GENERIC `"internal error"` message
    // — the inner discriminator (sqlx errors, file paths, parse
    // positions) MUST NOT reach the wire, only `tracing::error!` logs.
    #[tokio::test]
    async fn auth_error_response_backend_renders_500_with_generic_message() {
        let resp = auth_error_response(&AuthError::Backend("sqlx: table users not found".into()));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "backend_error");
        assert_eq!(
            body["error"]["message"], "internal error",
            "wire message must be generic — Backend's inner string is log-only"
        );
        let serialized = body.to_string();
        assert!(
            !serialized.contains("sqlx") && !serialized.contains("table users"),
            "Backend's inner discriminator must not appear in wire body: {serialized}"
        );
    }

    // M9 (#6 from verify-iter-2): MtlsMisconfigured maps to a generic
    // wire envelope (`code: internal_error`, message: "internal error")
    // so daemon misconfig discriminators are not leaked through 500s.
    // The discriminating string is logged at `tracing::error!` only
    // (see auth.rs auth_middleware).
    #[tokio::test]
    async fn auth_error_response_mtls_misconfigured_renders_generic_500() {
        let resp = auth_error_response(&AuthError::MtlsMisconfigured);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "internal_error");
        assert_eq!(
            body["error"]["message"], "internal error",
            "wire message must be generic — no operational discriminator"
        );
    }
}
