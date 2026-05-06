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

use crate::oauth::sealing::{SealingKey, SealingKeyError};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::SqlitePool;
use std::time::{SystemTime, UNIX_EPOCH};

/// In-memory OAuth session record. Tokens are unsealed on read,
/// resealed on write. Lifetime in memory is bounded by the caller
/// (the proxy hot path materializes only the access token, briefly).
#[derive(Clone)]
pub struct OauthSession {
    pub name: String,
    pub refresh_token: SecretString,
    pub access_token: Option<SecretString>,
    /// Unix seconds at which the access token expires. `None` only in
    /// the brief window between bootstrap (refresh-token sealed) and
    /// the daemon's first token-endpoint exchange (refresh-task or
    /// proxy-on-demand fills `access_token` + `access_token_expires_at`).
    pub access_token_expires_at: Option<i64>,
    /// Space-delimited scopes from the bootstrap response.
    pub scope: String,
    pub degraded: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl std::fmt::Debug for OauthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthSession")
            .field("name", &self.name)
            .field("refresh_token", &"<sealed>")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<sealed>"),
            )
            .field("access_token_expires_at", &self.access_token_expires_at)
            .field("scope", &self.scope)
            .field("degraded", &self.degraded)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl OauthSession {
    /// Stable session identifier per ADR-0005 D4. SHA-256 of
    /// `name + ':' + created_at`, truncated to 16 hex chars. Used as
    /// `details.oauth_session_id` in audit rows. Never derived from
    /// token material.
    pub fn audit_session_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.name.as_bytes());
        hasher.update(b":");
        hasher.update(self.created_at.to_string().as_bytes());
        let digest = hasher.finalize();
        // 8 bytes → 16 hex chars. Inline encoder to avoid adding the
        // `hex` crate; sha2 gives us a fixed-size GenericArray here.
        let mut out = String::with_capacity(16);
        for b in &digest[..8] {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

/// Errors from the OAuth session repository.
#[derive(Debug, thiserror::Error)]
pub enum OauthSessionError {
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

/// Repository for the `oauth_sessions` table. All writes go through
/// here so sealing is consistent. Cloneable; share across the daemon.
#[derive(Clone)]
pub struct OauthSessionRepository {
    pool: SqlitePool,
}

impl OauthSessionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create a fresh session row at first-time auth. Phase F.4
    /// bootstrap CLI calls this immediately after exchanging the
    /// authorization code for the initial token pair.
    pub async fn create(
        &self,
        key: &SealingKey,
        name: &str,
        refresh_token: &str,
        access_token: Option<&str>,
        access_token_expires_at: Option<i64>,
        scope: &str,
    ) -> Result<OauthSession, OauthSessionError> {
        let now = unix_now();
        let (refresh_ct, refresh_nonce) = key.seal(refresh_token.as_bytes())?;
        let access_sealed = match access_token {
            Some(at) => Some(key.seal(at.as_bytes())?),
            None => None,
        };

        sqlx::query(
            "INSERT INTO oauth_sessions (\
                name, refresh_token_ciphertext, refresh_token_nonce, \
                access_token_ciphertext, access_token_nonce, \
                access_token_expires_at, scope, degraded, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
        )
        .bind(name)
        .bind(&refresh_ct)
        .bind(&refresh_nonce)
        .bind(access_sealed.as_ref().map(|(c, _)| c))
        .bind(access_sealed.as_ref().map(|(_, n)| n))
        .bind(access_token_expires_at)
        .bind(scope)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(OauthSession {
            name: name.to_string(),
            refresh_token: SecretString::from(refresh_token.to_string()),
            access_token: access_token.map(|s| SecretString::from(s.to_string())),
            access_token_expires_at,
            scope: scope.to_string(),
            degraded: false,
            created_at: now,
            updated_at: now,
        })
    }

    /// Replace the access token (and optionally the refresh token, when
    /// the provider rotates it). Called by the background refresh task
    /// after a successful token-endpoint exchange.
    pub async fn update_tokens(
        &self,
        key: &SealingKey,
        name: &str,
        new_access_token: &str,
        new_access_token_expires_at: i64,
        new_refresh_token: Option<&str>,
    ) -> Result<(), OauthSessionError> {
        let now = unix_now();
        let (access_ct, access_nonce) = key.seal(new_access_token.as_bytes())?;

        if let Some(rt) = new_refresh_token {
            let (refresh_ct, refresh_nonce) = key.seal(rt.as_bytes())?;
            sqlx::query(
                "UPDATE oauth_sessions SET \
                    access_token_ciphertext = ?, access_token_nonce = ?, \
                    access_token_expires_at = ?, \
                    refresh_token_ciphertext = ?, refresh_token_nonce = ?, \
                    degraded = 0, updated_at = ? \
                 WHERE name = ?",
            )
            .bind(&access_ct)
            .bind(&access_nonce)
            .bind(new_access_token_expires_at)
            .bind(&refresh_ct)
            .bind(&refresh_nonce)
            .bind(now)
            .bind(name)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE oauth_sessions SET \
                    access_token_ciphertext = ?, access_token_nonce = ?, \
                    access_token_expires_at = ?, \
                    degraded = 0, updated_at = ? \
                 WHERE name = ?",
            )
            .bind(&access_ct)
            .bind(&access_nonce)
            .bind(new_access_token_expires_at)
            .bind(now)
            .bind(name)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Mark a session degraded after a failed refresh. Subsequent
    /// proxy calls return 503 with `oauth_refresh_failed` until the
    /// operator re-bootstraps. ADR-0005 D6.
    pub async fn mark_degraded(&self, name: &str) -> Result<(), OauthSessionError> {
        sqlx::query("UPDATE oauth_sessions SET degraded = 1, updated_at = ? WHERE name = ?")
            .bind(unix_now())
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Read an unsealed session by name. Returns `Ok(None)` for unknown
    /// names. Tokens are unsealed eagerly — caller controls scope.
    pub async fn get(
        &self,
        key: &SealingKey,
        name: &str,
    ) -> Result<Option<OauthSession>, OauthSessionError> {
        let row = sqlx::query(
            "SELECT name, refresh_token_ciphertext, refresh_token_nonce, \
                    access_token_ciphertext, access_token_nonce, \
                    access_token_expires_at, scope, degraded, created_at, updated_at \
             FROM oauth_sessions WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let refresh_ct: Vec<u8> = row.get("refresh_token_ciphertext");
        let refresh_nonce: Vec<u8> = row.get("refresh_token_nonce");
        let refresh_pt = key.unseal(&refresh_ct, &refresh_nonce)?;
        let refresh_token =
            SecretString::from(String::from_utf8(refresh_pt).map_err(|_| {
                OauthSessionError::Invariant("refresh-token plaintext is not UTF-8")
            })?);

        let access_ct: Option<Vec<u8>> = row.get("access_token_ciphertext");
        let access_nonce: Option<Vec<u8>> = row.get("access_token_nonce");
        let access_token = match (access_ct, access_nonce) {
            (Some(ct), Some(nonce)) => {
                let pt = key.unseal(&ct, &nonce)?;
                Some(SecretString::from(String::from_utf8(pt).map_err(|_| {
                    OauthSessionError::Invariant("access-token plaintext is not UTF-8")
                })?))
            }
            (None, None) => None,
            _ => {
                return Err(OauthSessionError::Invariant(
                    "access_token_ciphertext / access_token_nonce out of sync",
                ));
            }
        };

        let degraded: i64 = row.get("degraded");
        Ok(Some(OauthSession {
            name: row.get("name"),
            refresh_token,
            access_token,
            access_token_expires_at: row.get("access_token_expires_at"),
            scope: row.get("scope"),
            degraded: degraded != 0,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    /// Delete a session row entirely. Operator-initiated via
    /// `locksmith oauth revoke <name>`. Does NOT call the provider's
    /// revoke endpoint (deferred to v1.1+).
    pub async fn delete(&self, name: &str) -> Result<bool, OauthSessionError> {
        let result = sqlx::query("DELETE FROM oauth_sessions WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// List sessions whose `access_token_expires_at` is at or before
    /// the supplied threshold and which are not degraded. Used by the
    /// background refresh task. ADR-0005 D3.
    pub async fn list_pending_refresh(
        &self,
        threshold_unix_secs: i64,
    ) -> Result<Vec<String>, OauthSessionError> {
        let rows = sqlx::query(
            "SELECT name FROM oauth_sessions \
             WHERE degraded = 0 AND access_token_expires_at IS NOT NULL \
               AND access_token_expires_at <= ? \
             ORDER BY access_token_expires_at ASC",
        )
        .bind(threshold_unix_secs)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("name"))
            .collect())
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
    use crate::migrations::open_and_migrate;
    use secrecy::ExposeSecret;
    use tempfile::TempDir;

    async fn fresh_repo() -> (TempDir, OauthSessionRepository, SealingKey) {
        let dir = TempDir::new().unwrap();
        let pool = open_and_migrate(&dir.path().join("locksmith.db"))
            .await
            .unwrap();
        let repo = OauthSessionRepository::new(pool);
        let key = SealingKey::generate().unwrap();
        (dir, repo, key)
    }

    #[tokio::test]
    async fn create_and_get_roundtrip() {
        let (_dir, repo, key) = fresh_repo().await;
        let session = repo
            .create(
                &key,
                "codex",
                "refresh-token-abc",
                Some("access-token-xyz"),
                Some(unix_now() + 3600),
                "openai-api",
            )
            .await
            .unwrap();
        assert_eq!(session.name, "codex");
        assert_eq!(session.refresh_token.expose_secret(), "refresh-token-abc");
        assert_eq!(
            session.access_token.as_ref().unwrap().expose_secret(),
            "access-token-xyz"
        );

        let back = repo.get(&key, "codex").await.unwrap().unwrap();
        assert_eq!(back.refresh_token.expose_secret(), "refresh-token-abc");
        assert_eq!(
            back.access_token.as_ref().unwrap().expose_secret(),
            "access-token-xyz"
        );
        assert_eq!(back.scope, "openai-api");
        assert!(!back.degraded);
    }

    #[tokio::test]
    async fn update_tokens_replaces_access_only() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "x", "refresh-1", Some("access-1"), Some(100), "")
            .await
            .unwrap();
        repo.update_tokens(&key, "x", "access-2", 200, None)
            .await
            .unwrap();
        let s = repo.get(&key, "x").await.unwrap().unwrap();
        assert_eq!(s.refresh_token.expose_secret(), "refresh-1"); // unchanged
        assert_eq!(s.access_token.as_ref().unwrap().expose_secret(), "access-2");
        assert_eq!(s.access_token_expires_at, Some(200));
    }

    #[tokio::test]
    async fn update_tokens_replaces_both_when_refresh_supplied() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "x", "refresh-1", Some("access-1"), Some(100), "")
            .await
            .unwrap();
        repo.update_tokens(&key, "x", "access-2", 200, Some("refresh-2"))
            .await
            .unwrap();
        let s = repo.get(&key, "x").await.unwrap().unwrap();
        assert_eq!(s.refresh_token.expose_secret(), "refresh-2");
        assert_eq!(s.access_token.as_ref().unwrap().expose_secret(), "access-2");
    }

    #[tokio::test]
    async fn mark_degraded_clears_on_update() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "x", "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        repo.mark_degraded("x").await.unwrap();
        assert!(repo.get(&key, "x").await.unwrap().unwrap().degraded);

        // Successful refresh clears degraded flag (per ADR-0005 D6).
        repo.update_tokens(&key, "x", "at-2", 200, None)
            .await
            .unwrap();
        assert!(!repo.get(&key, "x").await.unwrap().unwrap().degraded);
    }

    #[tokio::test]
    async fn list_pending_refresh_filters_degraded() {
        let (_dir, repo, key) = fresh_repo().await;
        let now = unix_now();
        repo.create(&key, "due", "rt", Some("at"), Some(now), "")
            .await
            .unwrap();
        repo.create(&key, "future", "rt", Some("at"), Some(now + 3600), "")
            .await
            .unwrap();
        repo.create(&key, "degraded", "rt", Some("at"), Some(now), "")
            .await
            .unwrap();
        repo.mark_degraded("degraded").await.unwrap();

        // Threshold = now + 60 → "due" is pending; "future" not yet;
        // "degraded" is filtered out even though it's expired.
        let pending = repo.list_pending_refresh(now + 60).await.unwrap();
        assert_eq!(pending, vec!["due"]);
    }

    #[tokio::test]
    async fn audit_session_id_is_stable_for_same_session() {
        let (_dir, repo, key) = fresh_repo().await;
        let s1 = repo
            .create(&key, "x", "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        let id1 = s1.audit_session_id();
        // Reload — should get the same audit ID.
        let s2 = repo.get(&key, "x").await.unwrap().unwrap();
        assert_eq!(id1, s2.audit_session_id());
        assert_eq!(id1.len(), 16); // 8 bytes → 16 hex chars
    }

    #[tokio::test]
    async fn delete_clears_session() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "x", "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        assert!(repo.delete("x").await.unwrap());
        assert!(repo.get(&key, "x").await.unwrap().is_none());
        assert!(!repo.delete("x").await.unwrap()); // idempotent
    }

    #[tokio::test]
    async fn unseal_with_wrong_key_returns_sealing_error() {
        let (_dir, repo, key1) = fresh_repo().await;
        repo.create(&key1, "x", "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        let key2 = SealingKey::generate().unwrap();
        let err = repo.get(&key2, "x").await.unwrap_err();
        assert!(matches!(err, OauthSessionError::Sealing(_)));
    }
}
