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

/// Default OAuth session label. Used when the operator doesn't pass
/// `--label` on `oauth bootstrap` and when overrides don't carry
/// a `session_label`. Single-session deployments (the common case)
/// see `"default"` everywhere and never have to think about labels.
pub const DEFAULT_SESSION_LABEL: &str = "default";

/// In-memory OAuth session record. Tokens are unsealed on read,
/// resealed on write. Lifetime in memory is bounded by the caller
/// (the proxy hot path materializes only the access token, briefly).
#[derive(Clone)]
pub struct OauthSession {
    pub name: String,
    /// Session label (Phase G). Distinguishes multiple sessions under
    /// the same registration name — e.g., `(codex, "hermes")` vs
    /// `(codex, "openclaw")`. Defaults to `"default"` for shared-
    /// credential deployments.
    pub session_label: String,
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
    /// Phase G2 — provider-side account identifier extracted from the
    /// access-token JWT at bootstrap and refresh time. For codex this
    /// is the `chatgpt_account_id` claim; the proxy hot path reads it
    /// to inject the `ChatGPT-Account-ID` header alongside the bearer
    /// token. `None` for non-JWT access tokens (any other OAuth
    /// provider that doesn't follow the OpenAI claim shape) — those
    /// requests proceed without the header, which is the correct
    /// behavior for non-codex upstreams.
    pub account_id: Option<String>,
}

impl std::fmt::Debug for OauthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthSession")
            .field("name", &self.name)
            .field("session_label", &self.session_label)
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
            .field("account_id", &self.account_id)
            .finish()
    }
}

impl OauthSession {
    /// Stable session identifier per ADR-0005 D4. SHA-256 of
    /// `name + ':' + session_label + ':' + created_at`, truncated to
    /// 16 hex chars. Used as `details.oauth_session_id` in audit rows.
    /// Phase G adds session_label to the hash so two sessions under
    /// the same registration get distinct identifiers in audit. Never
    /// derived from token material.
    pub fn audit_session_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.name.as_bytes());
        hasher.update(b":");
        hasher.update(self.session_label.as_bytes());
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
    ///
    /// Phase G: takes a `session_label` to support multiple sessions
    /// per registration. Pre-Phase-G call sites pass
    /// [`DEFAULT_SESSION_LABEL`] to preserve existing behavior.
    ///
    /// Phase G2: when `access_token` parses as a JWT with the OpenAI
    /// `chatgpt_account_id` claim, the value is auto-extracted and
    /// stored in the `account_id` column for header injection on the
    /// proxy hot path. Non-JWT tokens (other OAuth providers) get
    /// `account_id = NULL`, which the proxy treats as "skip the
    /// chatgpt-account-id header" — the right answer for non-codex
    /// upstreams.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        key: &SealingKey,
        name: &str,
        session_label: &str,
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
        let account_id = access_token.and_then(crate::oauth::jwt::extract_chatgpt_account_id);

        sqlx::query(
            "INSERT INTO oauth_sessions (\
                name, session_label, refresh_token_ciphertext, refresh_token_nonce, \
                access_token_ciphertext, access_token_nonce, \
                access_token_expires_at, scope, degraded, created_at, updated_at, \
                account_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
        )
        .bind(name)
        .bind(session_label)
        .bind(&refresh_ct)
        .bind(&refresh_nonce)
        .bind(access_sealed.as_ref().map(|(c, _)| c))
        .bind(access_sealed.as_ref().map(|(_, n)| n))
        .bind(access_token_expires_at)
        .bind(scope)
        .bind(now)
        .bind(now)
        .bind(account_id.as_deref())
        .execute(&self.pool)
        .await?;

        Ok(OauthSession {
            name: name.to_string(),
            session_label: session_label.to_string(),
            refresh_token: SecretString::from(refresh_token.to_string()),
            access_token: access_token.map(|s| SecretString::from(s.to_string())),
            access_token_expires_at,
            scope: scope.to_string(),
            degraded: false,
            created_at: now,
            updated_at: now,
            account_id,
        })
    }

    /// Replace the access token (and optionally the refresh token, when
    /// the provider rotates it). Called by the background refresh task
    /// after a successful token-endpoint exchange.
    pub async fn update_tokens(
        &self,
        key: &SealingKey,
        name: &str,
        session_label: &str,
        new_access_token: &str,
        new_access_token_expires_at: i64,
        new_refresh_token: Option<&str>,
    ) -> Result<(), OauthSessionError> {
        let now = unix_now();
        let (access_ct, access_nonce) = key.seal(new_access_token.as_bytes())?;
        // Phase G2: re-derive account_id from each fresh access token.
        // Defensive against the rare case where a re-login swaps the
        // upstream identity bound to the session — the chatgpt-
        // account-id we inject must always match the access token in
        // hand.
        let new_account_id = crate::oauth::jwt::extract_chatgpt_account_id(new_access_token);

        if let Some(rt) = new_refresh_token {
            let (refresh_ct, refresh_nonce) = key.seal(rt.as_bytes())?;
            sqlx::query(
                "UPDATE oauth_sessions SET \
                    access_token_ciphertext = ?, access_token_nonce = ?, \
                    access_token_expires_at = ?, \
                    refresh_token_ciphertext = ?, refresh_token_nonce = ?, \
                    account_id = ?, \
                    degraded = 0, updated_at = ? \
                 WHERE name = ? AND session_label = ?",
            )
            .bind(&access_ct)
            .bind(&access_nonce)
            .bind(new_access_token_expires_at)
            .bind(&refresh_ct)
            .bind(&refresh_nonce)
            .bind(new_account_id.as_deref())
            .bind(now)
            .bind(name)
            .bind(session_label)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE oauth_sessions SET \
                    access_token_ciphertext = ?, access_token_nonce = ?, \
                    access_token_expires_at = ?, \
                    account_id = ?, \
                    degraded = 0, updated_at = ? \
                 WHERE name = ? AND session_label = ?",
            )
            .bind(&access_ct)
            .bind(&access_nonce)
            .bind(new_access_token_expires_at)
            .bind(new_account_id.as_deref())
            .bind(now)
            .bind(name)
            .bind(session_label)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Mark a session degraded after a failed refresh. Subsequent
    /// proxy calls return 503 with `oauth_refresh_failed` until the
    /// operator re-bootstraps. ADR-0005 D6.
    pub async fn mark_degraded(
        &self,
        name: &str,
        session_label: &str,
    ) -> Result<(), OauthSessionError> {
        sqlx::query(
            "UPDATE oauth_sessions SET degraded = 1, updated_at = ? \
             WHERE name = ? AND session_label = ?",
        )
        .bind(unix_now())
        .bind(name)
        .bind(session_label)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Read an unsealed session by `(name, session_label)`. Returns
    /// `Ok(None)` for unknown keys. Tokens are unsealed eagerly —
    /// caller controls scope.
    pub async fn get(
        &self,
        key: &SealingKey,
        name: &str,
        session_label: &str,
    ) -> Result<Option<OauthSession>, OauthSessionError> {
        let row = sqlx::query(
            "SELECT name, session_label, refresh_token_ciphertext, refresh_token_nonce, \
                    access_token_ciphertext, access_token_nonce, \
                    access_token_expires_at, scope, degraded, created_at, updated_at, \
                    account_id \
             FROM oauth_sessions WHERE name = ? AND session_label = ?",
        )
        .bind(name)
        .bind(session_label)
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
            session_label: row.get("session_label"),
            refresh_token,
            access_token,
            access_token_expires_at: row.get("access_token_expires_at"),
            scope: row.get("scope"),
            degraded: degraded != 0,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            account_id: row.get("account_id"),
        }))
    }

    /// Delete a session row entirely. Operator-initiated via
    /// `locksmith oauth revoke <name> [--label <label>]`. Does NOT
    /// call the provider's revoke endpoint (deferred to v1.1+).
    pub async fn delete(&self, name: &str, session_label: &str) -> Result<bool, OauthSessionError> {
        let result = sqlx::query("DELETE FROM oauth_sessions WHERE name = ? AND session_label = ?")
            .bind(name)
            .bind(session_label)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// List `(name, session_label)` pairs whose
    /// `access_token_expires_at` is at or before the supplied
    /// threshold and which are not degraded. Used by the background
    /// refresh task. ADR-0005 D3.
    pub async fn list_pending_refresh(
        &self,
        threshold_unix_secs: i64,
    ) -> Result<Vec<(String, String)>, OauthSessionError> {
        let rows = sqlx::query(
            "SELECT name, session_label FROM oauth_sessions \
             WHERE degraded = 0 AND access_token_expires_at IS NOT NULL \
               AND access_token_expires_at <= ? \
             ORDER BY access_token_expires_at ASC",
        )
        .bind(threshold_unix_secs)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("name"),
                    r.get::<String, _>("session_label"),
                )
            })
            .collect())
    }

    /// List all `(name, session_label)` pairs in the table. Used by
    /// `locksmith oauth list` (Phase G CLI) for operator visibility.
    /// Does not unseal tokens — pure metadata query.
    pub async fn list_all(
        &self,
    ) -> Result<Vec<(String, String, bool, Option<i64>)>, OauthSessionError> {
        let rows = sqlx::query(
            "SELECT name, session_label, degraded, access_token_expires_at \
             FROM oauth_sessions ORDER BY name, session_label",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let degraded: i64 = r.get("degraded");
                (
                    r.get::<String, _>("name"),
                    r.get::<String, _>("session_label"),
                    degraded != 0,
                    r.get::<Option<i64>, _>("access_token_expires_at"),
                )
            })
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

    const DEF: &str = DEFAULT_SESSION_LABEL;

    #[tokio::test]
    async fn create_and_get_roundtrip() {
        let (_dir, repo, key) = fresh_repo().await;
        let session = repo
            .create(
                &key,
                "codex",
                DEF,
                "refresh-token-abc",
                Some("access-token-xyz"),
                Some(unix_now() + 3600),
                "openai-api",
            )
            .await
            .unwrap();
        assert_eq!(session.name, "codex");
        assert_eq!(session.session_label, DEF);
        assert_eq!(session.refresh_token.expose_secret(), "refresh-token-abc");
        assert_eq!(
            session.access_token.as_ref().unwrap().expose_secret(),
            "access-token-xyz"
        );

        let back = repo.get(&key, "codex", DEF).await.unwrap().unwrap();
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
        repo.create(&key, "x", DEF, "refresh-1", Some("access-1"), Some(100), "")
            .await
            .unwrap();
        repo.update_tokens(&key, "x", DEF, "access-2", 200, None)
            .await
            .unwrap();
        let s = repo.get(&key, "x", DEF).await.unwrap().unwrap();
        assert_eq!(s.refresh_token.expose_secret(), "refresh-1"); // unchanged
        assert_eq!(s.access_token.as_ref().unwrap().expose_secret(), "access-2");
        assert_eq!(s.access_token_expires_at, Some(200));
    }

    #[tokio::test]
    async fn update_tokens_replaces_both_when_refresh_supplied() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "x", DEF, "refresh-1", Some("access-1"), Some(100), "")
            .await
            .unwrap();
        repo.update_tokens(&key, "x", DEF, "access-2", 200, Some("refresh-2"))
            .await
            .unwrap();
        let s = repo.get(&key, "x", DEF).await.unwrap().unwrap();
        assert_eq!(s.refresh_token.expose_secret(), "refresh-2");
        assert_eq!(s.access_token.as_ref().unwrap().expose_secret(), "access-2");
    }

    #[tokio::test]
    async fn mark_degraded_clears_on_update() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "x", DEF, "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        repo.mark_degraded("x", DEF).await.unwrap();
        assert!(repo.get(&key, "x", DEF).await.unwrap().unwrap().degraded);

        // Successful refresh clears degraded flag (per ADR-0005 D6).
        repo.update_tokens(&key, "x", DEF, "at-2", 200, None)
            .await
            .unwrap();
        assert!(!repo.get(&key, "x", DEF).await.unwrap().unwrap().degraded);
    }

    #[tokio::test]
    async fn list_pending_refresh_filters_degraded() {
        let (_dir, repo, key) = fresh_repo().await;
        let now = unix_now();
        repo.create(&key, "due", DEF, "rt", Some("at"), Some(now), "")
            .await
            .unwrap();
        repo.create(&key, "future", DEF, "rt", Some("at"), Some(now + 3600), "")
            .await
            .unwrap();
        repo.create(&key, "degraded", DEF, "rt", Some("at"), Some(now), "")
            .await
            .unwrap();
        repo.mark_degraded("degraded", DEF).await.unwrap();

        // Threshold = now + 60 → "due" is pending; "future" not yet;
        // "degraded" is filtered out even though it's expired.
        let pending = repo.list_pending_refresh(now + 60).await.unwrap();
        assert_eq!(pending, vec![("due".to_string(), DEF.to_string())]);
    }

    #[tokio::test]
    async fn audit_session_id_is_stable_for_same_session() {
        let (_dir, repo, key) = fresh_repo().await;
        let s1 = repo
            .create(&key, "x", DEF, "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        let id1 = s1.audit_session_id();
        // Reload — should get the same audit ID.
        let s2 = repo.get(&key, "x", DEF).await.unwrap().unwrap();
        assert_eq!(id1, s2.audit_session_id());
        assert_eq!(id1.len(), 16); // 8 bytes → 16 hex chars
    }

    #[tokio::test]
    async fn delete_clears_session() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "x", DEF, "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        assert!(repo.delete("x", DEF).await.unwrap());
        assert!(repo.get(&key, "x", DEF).await.unwrap().is_none());
        assert!(!repo.delete("x", DEF).await.unwrap()); // idempotent
    }

    #[tokio::test]
    async fn unseal_with_wrong_key_returns_sealing_error() {
        let (_dir, repo, key1) = fresh_repo().await;
        repo.create(&key1, "x", DEF, "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        let key2 = SealingKey::generate().unwrap();
        let err = repo.get(&key2, "x", DEF).await.unwrap_err();
        assert!(matches!(err, OauthSessionError::Sealing(_)));
    }

    // Phase G: label semantics.

    #[tokio::test]
    async fn two_labels_under_same_name_coexist() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "codex", "hermes", "rt-h", Some("at-h"), Some(100), "")
            .await
            .unwrap();
        repo.create(
            &key,
            "codex",
            "openclaw",
            "rt-o",
            Some("at-o"),
            Some(200),
            "",
        )
        .await
        .unwrap();

        let h = repo.get(&key, "codex", "hermes").await.unwrap().unwrap();
        let o = repo.get(&key, "codex", "openclaw").await.unwrap().unwrap();
        assert_eq!(h.refresh_token.expose_secret(), "rt-h");
        assert_eq!(o.refresh_token.expose_secret(), "rt-o");
        // Audit IDs are distinct because session_label is part of the
        // hash input.
        assert_ne!(h.audit_session_id(), o.audit_session_id());
    }

    #[tokio::test]
    async fn get_with_wrong_label_returns_none() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "codex", "hermes", "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        // Asking for the same name under a label we never created
        // returns None rather than spilling the wrong label's session.
        assert!(repo.get(&key, "codex", "openclaw").await.unwrap().is_none());
        assert!(repo.get(&key, "codex", DEF).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_one_label_leaves_other_intact() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "codex", "hermes", "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        repo.create(&key, "codex", "openclaw", "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        assert!(repo.delete("codex", "hermes").await.unwrap());
        assert!(repo.get(&key, "codex", "hermes").await.unwrap().is_none());
        // openclaw's session is untouched.
        assert!(repo.get(&key, "codex", "openclaw").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn list_pending_refresh_returns_label_too() {
        let (_dir, repo, key) = fresh_repo().await;
        let now = unix_now();
        repo.create(&key, "codex", "hermes", "rt", Some("at"), Some(now), "")
            .await
            .unwrap();
        repo.create(&key, "codex", "openclaw", "rt", Some("at"), Some(now), "")
            .await
            .unwrap();
        let pending = repo.list_pending_refresh(now + 60).await.unwrap();
        assert_eq!(pending.len(), 2);
        assert!(
            pending
                .iter()
                .any(|p| p == &("codex".to_string(), "hermes".to_string()))
        );
        assert!(
            pending
                .iter()
                .any(|p| p == &("codex".to_string(), "openclaw".to_string()))
        );
    }

    #[tokio::test]
    async fn list_all_returns_all_label_pairs() {
        let (_dir, repo, key) = fresh_repo().await;
        repo.create(&key, "codex", DEF, "rt", Some("at"), Some(100), "")
            .await
            .unwrap();
        repo.create(&key, "codex", "hermes", "rt", Some("at"), Some(200), "")
            .await
            .unwrap();
        repo.create(&key, "anthropic-oauth", DEF, "rt", None, None, "")
            .await
            .unwrap();
        let rows = repo.list_all().await.unwrap();
        assert_eq!(rows.len(), 3);
    }
}
