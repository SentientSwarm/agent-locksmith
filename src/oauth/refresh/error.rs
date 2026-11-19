/// Errors from a single refresh attempt. Each variant maps to an
/// audit `details.cause` value per ADR-0005 D4.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("OAuth refresh outcome uncertain or unavailable; reconnect with fresh credentials")]
    ReconnectRequired,
    #[error("registration {0} disappeared from catalog before refresh")]
    RegistrationGone(String),

    #[error("registration {0} is not an OAuth shape (programming error)")]
    NotOauth(String),

    #[error("network error contacting token endpoint: {0}")]
    Network(String),

    #[error("provider rejected refresh ({status})")]
    Revoked { status: u16 },

    #[error("provider error during refresh ({status})")]
    ProviderError { status: u16 },

    /// AGENT-302: token calls never follow redirects (a followed one could
    /// resend the refresh token to another host), so any 3xx fails the
    /// call; this variant is the redirects (301, 302, 303, 307, 308).
    #[error(
        "token endpoint answered a redirect ({status}); token calls do not \
         follow redirects, so set token_url to the final URL"
    )]
    Redirected { status: u16 },

    #[error("provider returned malformed token response: {0}")]
    BadResponse(String),

    #[error("failed to persist refreshed tokens: {0}")]
    Persist(String),
}

impl RefreshError {
    /// Audit cause label per ADR-0005 D4. Distinguishes operator-
    /// actionable failures (`revoked`) from transient provider
    /// problems (`provider_5xx`) so dashboards can surface them
    /// differently.
    pub fn audit_cause(&self) -> &'static str {
        match self {
            Self::ReconnectRequired => "reconnect_required",
            RefreshError::RegistrationGone(_) => "registration_gone",
            RefreshError::NotOauth(_) => "not_oauth",
            RefreshError::Network(_) => "network_error",
            RefreshError::Revoked { .. } => "revoked",
            RefreshError::ProviderError { .. } => "provider_5xx",
            RefreshError::Redirected { .. } => "token_redirect",
            RefreshError::BadResponse(_) => "bad_response",
            RefreshError::Persist(_) => "persist_failed",
        }
    }

    /// The token endpoint's HTTP status, when the failure is its answer.
    /// `provider_5xx` also covers a 300 or 304 (AGENT-328), so the
    /// operational log carries the status to tell them apart.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Revoked { status }
            | Self::ProviderError { status }
            | Self::Redirected { status } => Some(*status),
            _ => None,
        }
    }
}
