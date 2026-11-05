//! `OauthSession` record + sqlx CRUD on the `oauth_sessions` table.
//! Phase F.3.
//!
//! Wire shape vs storage shape:
//!
//! - **Storage (DB)**: AES-GCM ciphertext + nonce columns for refresh
//!   plus access tokens. Sealing key from
//!   [`crate::oauth::sealing::SealingKey`].
//! - **In-memory (`OauthSession`)**: cleartext refresh + access tokens
//!   in `SecretString` (zeroized on drop), with the materialized
//!   `expires_at` epoch. Hot-path callers never touch DB rows
//!   directly.
//!
//! The sealing key never enters the DB layer — repo callers supply a
//! `&SealingKey` for seal/unseal alongside each operation. This keeps
//! the sealing surface auditable: anywhere the key is used, the call
//! site is explicit.

use crate::oauth::sealing::SealingKeyError;
use sqlx::SqlitePool;
use std::time::{SystemTime, UNIX_EPOCH};

mod attempt;
mod lifecycle;
mod read;
mod record;
mod write;
pub use attempt::RefreshAttempt;
pub use record::OauthSession;

/// The default must still be explicitly selected in an account binding.
/// Secret-free listing: name, label, degraded, expiry, pending.
pub type SessionMetadata = (String, String, bool, Option<i64>, bool);

pub const DEFAULT_SESSION_LABEL: &str = "default";

/// Errors from the OAuth session repository.
#[derive(Debug, thiserror::Error)]
pub enum OauthSessionError {
    #[error("OAuth session changed or is absent")]
    Stale,

    #[error("OAuth account kind is not supported by this interface")]
    UnsupportedKind,

    #[error("sealing: {0}")]
    Sealing(#[from] SealingKeyError),

    #[error("database: {0}")]
    Database(String),

    /// Internal invariant violation: a row's access_token_ciphertext is
    /// non-NULL but access_token_nonce is NULL (or vice versa). Should
    /// never happen if writes go through this repo.
    #[error("invariant violation: {0}")]
    Invariant(&'static str),
}

impl From<sqlx::Error> for OauthSessionError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e.to_string())
    }
}

/// Sealed custody; asynchronous writers must carry their original snapshot.
#[derive(Clone)]
pub struct OauthSessionRepository {
    pool: SqlitePool,
}

impl OauthSessionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
