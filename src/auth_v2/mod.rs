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
    /// Underlying repository / IO failure. 500.
    #[error("backend: {0}")]
    Backend(String),
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
            AuthError::Backend(_) => 500,
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
        }
    }
}
