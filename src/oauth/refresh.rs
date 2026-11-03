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
    ///
    /// Phase G: keys on `(name, session_label)` so two labels under
    /// the same registration get distinct locks. Refreshes for two
    /// labels can run concurrently without contention.
    pub async fn get(&self, name: &str, session_label: &str) -> Arc<Mutex<()>> {
        let mut map = self.inner.lock().await;
        let key = format!("{name}\u{1f}{session_label}");
        map.entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

mod exchange;
pub use exchange::refresh_selected_session;

/// Operator bootstrap explicitly uses the current registration metadata.
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
    refresh_selected_session(repo, &registration.auth, key, client, session).await
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

    #[error("provider rejected refresh ({status})")]
    Revoked { status: u16 },

    #[error("provider error during refresh ({status})")]
    ProviderError { status: u16 },

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
#[allow(clippy::too_many_arguments)]
pub async fn run(
    repo: OauthSessionRepository,
    catalog: Arc<arc_swap::ArcSwap<Catalog>>,
    bindings: crate::repo::AgentCredentialRepository,
    key: SealingKey,
    locks: RefreshLockMap,
    operational_log: Option<Arc<crate::operational_log_sink::OperationalLogEmitter>>,
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
                    Ok(items) if items.is_empty() => {}
                    Ok(items) => {
                        for (name, session_label) in items {
                            if catalog.load().lookup_active(&name).is_none() { continue; }
                            // Take the per-session lock so concurrent on-
                            // demand refresh from the proxy hot path
                            // can't race us. Phase G: lock keys on
                            // (name, session_label).
                            let lock = locks.get(&name, &session_label).await;
                            let _guard = lock.lock().await;

                            let selection = match selected_source(&bindings, &name, &session_label).await {
                                Ok(Some(spec)) => spec,
                                Ok(None) => continue,
                                Err(_) => {
                                    warn!(name = %name, session_label = %session_label,
                                        "OAuth selection unavailable or conflicting; refresh skipped");
                                    continue;
                                }
                            };
                            // Re-read inside the lock — another caller
                            // (proxy hot path) may have already
                            // refreshed.
                            let session = match repo.get(&key, &name, &session_label).await {
                                Ok(Some(s)) if !s.degraded => s,
                                Ok(_) => continue,
                                Err(e) => {
                                    warn!(
                                        name = %name,
                                        session_label = %session_label,
                                        error = %e,
                                        "oauth refresh: get failed; skipping",
                                    );
                                    continue;
                                }
                            };
                            if session.access_token_expires_at.is_some_and(|exp| exp > threshold) {
                                continue;
                            }

                            match refresh_selected_session(&repo, &selection, &key, &client, &session).await {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!(
                                        name = %name,
                                        session_label = %session_label,
                                        cause = e.audit_cause(),
                                        error = %e,
                                        "oauth refresh failed; marking session degraded",
                                    );
                                    // Phase J / M2 (LOG-2, oauth emit site):
                                    // record the refresh degradation on the
                                    // operational-log stream. Non-secret —
                                    // registration name + session label +
                                    // audit cause only; never the token.
                                    if let Some(emitter) = operational_log.as_ref() {
                                        emitter.emit(
                                            crate::repo::LogLevel::Warn,
                                            crate::repo::LogComponent::Oauth,
                                            "oauth_refresh_degraded",
                                            "oauth refresh failed; session marked degraded",
                                            Some(serde_json::json!({
                                                "registration": name,
                                                "session_label": session_label,
                                                "cause": e.audit_cause(),
                                            })),
                                        );
                                    }
                                    if let Err(persist_err) = repo
                                        .mark_degraded(&name, &session_label)
                                        .await
                                    {
                                        warn!(
                                            name = %name,
                                            session_label = %session_label,
                                            error = %persist_err,
                                            "mark_degraded failed",
                                        );
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
    async fn lock_map_returns_same_lock_for_same_name_and_label() {
        let map = RefreshLockMap::new();
        let l1 = map.get("codex", "default").await;
        let l2 = map.get("codex", "default").await;
        assert!(Arc::ptr_eq(&l1, &l2));

        let l3 = map.get("anthropic-oauth", "default").await;
        assert!(!Arc::ptr_eq(&l1, &l3));
    }

    // Phase G: distinct labels under the same registration name get
    // distinct locks, so two labels can refresh concurrently without
    // serializing on each other.
    #[tokio::test]
    async fn lock_map_distinguishes_labels_under_same_name() {
        let map = RefreshLockMap::new();
        let l_default = map.get("codex", "default").await;
        let l_hermes = map.get("codex", "hermes").await;
        let l_openclaw = map.get("codex", "openclaw").await;
        assert!(!Arc::ptr_eq(&l_default, &l_hermes));
        assert!(!Arc::ptr_eq(&l_hermes, &l_openclaw));
        assert!(!Arc::ptr_eq(&l_default, &l_openclaw));
    }
}

/// Use only an unambiguous explicit selection for this shared session.
/// Never substitute a registration template, including after it has been edited.
pub(crate) async fn selected_source(
    bindings: &crate::repo::AgentCredentialRepository,
    name: &str,
    session_label: &str,
) -> Result<Option<AuthSpec>, ()> {
    let rows = bindings.list_all().await.map_err(|_| ())?;
    consensus(
        rows.iter()
            .filter(|row| {
                row.registration == name
                    && row.auth_spec.oauth_session_label() == Some(session_label)
                    && !session_label.trim().is_empty()
            })
            .map(|row| &row.auth_spec),
    )
}

/// Shared-session metadata rule, also used inside the offline migration transaction.
pub(crate) fn consensus<'a>(
    specs: impl Iterator<Item = &'a AuthSpec>,
) -> Result<Option<AuthSpec>, ()> {
    let mut selected = None;
    for spec in specs {
        if selected_parameters(spec).is_none()
            || selected.as_ref().is_some_and(|prior| prior != spec)
        {
            return Err(());
        }
        selected = Some(spec.clone());
    }
    Ok(selected)
}

/// Public OAuth metadata must be usable before a selected session is read.
pub fn selected_parameters(spec: &AuthSpec) -> Option<(&str, &str)> {
    let (url, client) = match spec {
        AuthSpec::OauthPkce {
            token_url,
            client_id,
            ..
        }
        | AuthSpec::OauthDeviceCode {
            token_url,
            client_id,
            ..
        } => (token_url, client_id),
        _ => return None,
    };
    let parsed = reqwest::Url::parse(url).ok()?;
    if client.trim().is_empty()
        || !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
    {
        return None;
    }
    Some((url.as_str(), client.as_str()))
}

#[cfg(test)]
#[path = "refresh/selection_tests.rs"]
mod selection_tests;
