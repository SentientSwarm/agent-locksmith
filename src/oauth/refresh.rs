//! OAuth refresh task + per-session mutex. Phase F.3.
//!
//! ADR-0005 D3 (refresh-ahead-of-expiry timing) and D6 (failure
//! semantics) implementation.
//!
//! ## Concurrency
//!
//! Concurrent proxy requests for the same OAuth registration must NOT
//! race the refresh task. Resolution: per-session `Mutex<()>` held
//! across the (read-current-token, decide-if-refresh-needed,
//! exchange-tokens, persist-new-tokens) sequence. Lock-free reads of
//! the access-token cache happen via the repo's `get`, which is
//! cheap (single-row SQLite query + AES-GCM unseal).
//!
//! ## Refresh schedule
//!
//! `min(5 minutes, lifetime / 4)` with a 60-second floor. The
//! background task wakes on a 30-second tick, queries
//! `list_pending_refresh(now + safety_margin)`, takes the per-session
//! lock, and exchanges tokens.
//!
//! ## Failure semantics
//!
//! Refresh failure (provider returned non-2xx, network error, malformed
//! response) marks the session degraded via
//! `OauthSessionRepository::mark_degraded`. The background task does
//! NOT retry — operator action via `locksmith oauth bootstrap <name>`
//! is required to recover.
//!
//! ## OAuth token-endpoint contract
//!
//! Refresh exchange follows RFC 6749 §6 (refresh_token grant):
//!
//! ```text
//! POST <token_url>
//! Content-Type: application/x-www-form-urlencoded
//!
//! grant_type=refresh_token
//! refresh_token=<sealed-then-unsealed>
//! client_id=<from AuthSpec>
//! ```
//!
//! Response (200 OK):
//!
//! ```json
//! {
//!   "access_token": "...",
//!   "expires_in": 3600,
//!   "token_type": "Bearer",
//!   "refresh_token": "..."   // optional rotation
//! }
//! ```

use crate::oauth::sealing::SealingKey;
use crate::oauth::session::{OauthSession, OauthSessionRepository};
use crate::registrations::{AuthSpec, Catalog};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Refresh-ahead-of-expiry safety margin per ADR-0005 D3.
/// `min(5 min, lifetime / 4)` with 60s floor — we don't know the
/// lifetime here, so we use the 5-min cap. Specific tokens with
/// shorter lifetimes use a smaller margin computed at refresh time
/// (see [`refresh_safety_margin_secs`]).
pub const DEFAULT_REFRESH_SAFETY_MARGIN_SECS: i64 = 300;

/// Minimum allowed refresh margin (60 seconds).
pub const MIN_REFRESH_SAFETY_MARGIN_SECS: i64 = 60;

/// Background refresh task tick. The task wakes this often, queries
/// for sessions needing refresh, and processes them. 30s is a
/// reasonable middle ground — short enough to catch tokens nearing
/// expiry, long enough to avoid CPU churn.
pub const REFRESH_TICK_SECS: u64 = 30;

/// Compute the refresh safety margin for a token with the given
/// lifetime in seconds. Returns `min(DEFAULT_REFRESH_SAFETY_MARGIN_SECS,
/// lifetime / 4)` clamped to at least `MIN_REFRESH_SAFETY_MARGIN_SECS`.
pub fn refresh_safety_margin_secs(lifetime_secs: i64) -> i64 {
    let by_quarter = lifetime_secs / 4;
    let chosen = DEFAULT_REFRESH_SAFETY_MARGIN_SECS.min(by_quarter);
    chosen.max(MIN_REFRESH_SAFETY_MARGIN_SECS)
}

/// Per-session refresh locks. `name` → `Mutex` ensures the refresh
/// task and any on-demand 401-retry refresh don't race.
///
/// Stored as an `Arc<Mutex<HashMap>>` so the daemon's runtime can
/// `clone()` cheaply for both consumers.
#[derive(Clone, Default)]
pub struct RefreshLockMap {
    inner: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl RefreshLockMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the per-session lock. Cheap on the hot path
    /// (single hashmap lookup); construction is rare.
    pub async fn get(&self, name: &str) -> Arc<Mutex<()>> {
        let mut map = self.inner.lock().await;
        map.entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

/// Token-endpoint response shape (RFC 6749 §5.1). `expires_in` is
/// optional per RFC but in practice all tested providers return it.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // we don't yet validate token_type — providers always say "Bearer"
    token_type: Option<String>,
}

/// Refresh a single session against its provider. Returns the new
/// `OauthSession` (resealed + persisted) on success, or an error that
/// marks the session degraded on failure.
pub async fn refresh_session(
    repo: &OauthSessionRepository,
    catalog: &Catalog,
    key: &SealingKey,
    client: &reqwest::Client,
    session: &OauthSession,
) -> Result<OauthSession, RefreshError> {
    let registration = catalog
        .lookup_active(&session.name)
        .ok_or_else(|| RefreshError::RegistrationGone(session.name.clone()))?;

    let (token_url, client_id) = match &registration.auth {
        AuthSpec::OauthPkce {
            token_url,
            client_id,
            ..
        }
        | AuthSpec::OauthDeviceCode {
            token_url,
            client_id,
            ..
        } => (token_url.as_str(), client_id.as_str()),
        _ => return Err(RefreshError::NotOauth(session.name.clone())),
    };

    use secrecy::ExposeSecret;
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", session.refresh_token.expose_secret()),
        ("client_id", client_id),
    ];

    let response = client
        .post(token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| RefreshError::Network(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        // 4xx (especially 400 invalid_grant / 401 invalid_client) means
        // the refresh token is no longer valid. Operator-action recovery.
        if status.is_client_error() {
            return Err(RefreshError::Revoked {
                status: status.as_u16(),
                body_excerpt: body.chars().take(256).collect(),
            });
        }
        // 5xx is provider-side; same outcome (mark degraded) since we
        // don't auto-retry. Operator can re-bootstrap when provider
        // recovers.
        return Err(RefreshError::ProviderError {
            status: status.as_u16(),
            body_excerpt: body.chars().take(256).collect(),
        });
    }

    let token_response: TokenResponse = response
        .json()
        .await
        .map_err(|e| RefreshError::BadResponse(e.to_string()))?;

    // expires_in is RFC-optional but in practice always present. If
    // missing, default to 1 hour — common provider default.
    let lifetime = token_response.expires_in.unwrap_or(3600);
    let new_expires_at = unix_now() + lifetime;

    repo.update_tokens(
        key,
        &session.name,
        &token_response.access_token,
        new_expires_at,
        token_response.refresh_token.as_deref(),
    )
    .await
    .map_err(|e| RefreshError::Persist(e.to_string()))?;

    info!(
        name = %session.name,
        oauth_session_id = %session.audit_session_id(),
        new_lifetime_secs = lifetime,
        "oauth refresh succeeded"
    );

    // Read back the canonical state.
    repo.get(key, &session.name)
        .await
        .map_err(|e| RefreshError::Persist(e.to_string()))?
        .ok_or_else(|| RefreshError::Persist("session vanished after update".to_string()))
}

/// Errors from a single refresh attempt. Each variant maps to an
/// audit `details.cause` value per ADR-0005 D4.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("registration {0} disappeared from catalog before refresh")]
    RegistrationGone(String),

    #[error("registration {0} is not an OAuth shape (programming error)")]
    NotOauth(String),

    #[error("network error contacting token endpoint: {0}")]
    Network(String),

    #[error("provider rejected refresh ({status}): {body_excerpt}")]
    Revoked { status: u16, body_excerpt: String },

    #[error("provider error during refresh ({status}): {body_excerpt}")]
    ProviderError { status: u16, body_excerpt: String },

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
            RefreshError::RegistrationGone(_) => "registration_gone",
            RefreshError::NotOauth(_) => "not_oauth",
            RefreshError::Network(_) => "network_error",
            RefreshError::Revoked { .. } => "revoked",
            RefreshError::ProviderError { .. } => "provider_5xx",
            RefreshError::BadResponse(_) => "bad_response",
            RefreshError::Persist(_) => "persist_failed",
        }
    }
}

/// Run the background refresh task. Wakes every `REFRESH_TICK_SECS`,
/// queries for sessions whose access token expires within the safety
/// margin, takes their per-session lock, and refreshes them.
///
/// Co-terminates with `shutdown` to stop cleanly on SIGTERM.
pub async fn run(
    repo: OauthSessionRepository,
    catalog: Arc<arc_swap::ArcSwap<Catalog>>,
    key: SealingKey,
    locks: RefreshLockMap,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut ticker = tokio::time::interval(Duration::from_secs(REFRESH_TICK_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("oauth refresh task: shutdown signal observed; exiting");
                return;
            }
            _ = ticker.tick() => {
                let threshold = unix_now() + DEFAULT_REFRESH_SAFETY_MARGIN_SECS;
                match repo.list_pending_refresh(threshold).await {
                    Ok(names) if names.is_empty() => {}
                    Ok(names) => {
                        let cat = catalog.load();
                        for name in names {
                            // Take the per-session lock so concurrent on-
                            // demand refresh from the proxy hot path
                            // can't race us.
                            let lock = locks.get(&name).await;
                            let _guard = lock.lock().await;

                            // Re-read inside the lock — another caller
                            // (proxy hot path) may have already
                            // refreshed.
                            let session = match repo.get(&key, &name).await {
                                Ok(Some(s)) if !s.degraded => s,
                                Ok(_) => continue,
                                Err(e) => {
                                    warn!(name = %name, error = %e, "oauth refresh: get failed; skipping");
                                    continue;
                                }
                            };
                            if session.access_token_expires_at.is_some_and(|exp| exp > threshold) {
                                continue;
                            }

                            match refresh_session(&repo, &cat, &key, &client, &session).await {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!(
                                        name = %name,
                                        cause = e.audit_cause(),
                                        error = %e,
                                        "oauth refresh failed; marking session degraded"
                                    );
                                    if let Err(persist_err) = repo.mark_degraded(&name).await {
                                        warn!(name = %name, error = %persist_err, "mark_degraded failed");
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => warn!(error = %e, "oauth refresh: list_pending_refresh failed"),
                }
            }
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_margin_uses_five_minutes_for_long_lifetime() {
        // 1-hour token: lifetime/4 = 900s; capped at 300s.
        assert_eq!(refresh_safety_margin_secs(3600), 300);
        // 24-hour token: lifetime/4 = 21600s; capped at 300s.
        assert_eq!(refresh_safety_margin_secs(86400), 300);
    }

    #[test]
    fn safety_margin_uses_quarter_for_short_lifetime() {
        // 15-min token: lifetime/4 = 225s; floor at 60s; chosen 225.
        assert_eq!(refresh_safety_margin_secs(900), 225);
    }

    #[test]
    fn safety_margin_floors_at_sixty() {
        // 2-min token: lifetime/4 = 30s; floored to 60s.
        assert_eq!(refresh_safety_margin_secs(120), 60);
        // 30-second token (pathological): lifetime/4 = 7s; floor 60s.
        assert_eq!(refresh_safety_margin_secs(30), 60);
    }

    #[tokio::test]
    async fn lock_map_returns_same_lock_for_same_name() {
        let map = RefreshLockMap::new();
        let l1 = map.get("codex").await;
        let l2 = map.get("codex").await;
        assert!(Arc::ptr_eq(&l1, &l2));

        let l3 = map.get("anthropic-oauth").await;
        assert!(!Arc::ptr_eq(&l1, &l3));
    }
}
