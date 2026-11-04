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
//! A committed pre-I/O claim makes uncertain custody unavailable. Only the
//! complete pair's successful commit clears it; restart never replays it.
//! Explicit local revoke and freshly obtained credentials recover the account.
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
    pub owner: RefreshOwner,
}

impl RefreshLockMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_owner(owner: RefreshOwner) -> Self {
        Self {
            owner,
            ..Self::default()
        }
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

mod owner;
pub use owner::RefreshOwner;

mod exchange;
mod failure;
pub use exchange::refresh_selected_session;
use failure::record_failure;

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

mod error;
pub use error::RefreshError;

mod background;
pub use background::run;

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;

mod source;
pub use source::selected_parameters;
pub(crate) use source::{consensus, selected_source};

#[cfg(test)]
#[path = "refresh/selection_tests.rs"]
mod selection_tests;

#[cfg(test)]
pub(crate) mod recovery_barrier;
#[cfg(test)]
mod recovery_process;
