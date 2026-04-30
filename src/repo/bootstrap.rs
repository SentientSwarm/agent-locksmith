//! Bootstrap-token repository (T2.6 / C-9). SPEC §4.2.11.

use super::agent::RepoError;
use crate::argon2_helper;
use crate::token::{StructuredToken, TokenNamespace};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapScope {
    pub tool_allowlist: Option<Vec<String>>,
    pub expires_at: Option<i64>,
    pub single_use: bool,
}

#[derive(Debug, Clone)]
pub struct BootstrapTokenRecord {
    pub id: i64,
    pub public_id: String,
    pub scope: BootstrapScope,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub used_at: Option<i64>,
    pub used_by_agent_id: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Clone)]
pub struct BootstrapTokenRepository {
    pool: SqlitePool,
}

impl BootstrapTokenRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn mint(
        &self,
        scope: BootstrapScope,
        created_by: &str,
    ) -> Result<(String, SecretString), RepoError> {
        let token = StructuredToken::generate(TokenNamespace::Bootstrap);
        let secret_hash =
            argon2_helper::hash(&SecretString::from(token.secret.expose().to_string()))?;
        let scope_json = serde_json::to_string(&scope)?;
        let now = unix_now();
        let public_id = token.public_id.as_str().to_string();
        let secret = SecretString::from(token.secret.expose().to_string());
        sqlx::query(
            "INSERT INTO bootstrap_tokens \
             (public_id, secret_hash, scope, created_by, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&public_id)
        .bind(&secret_hash)
        .bind(&scope_json)
        .bind(created_by)
        .bind(now)
        .bind(scope.expires_at)
        .execute(&self.pool)
        .await?;
        Ok((public_id, secret))
    }

    pub async fn list(&self) -> Result<Vec<BootstrapTokenRecord>, RepoError> {
        let rows = sqlx::query_as::<_, BootstrapRow>(
            "SELECT id, public_id, scope, created_by, created_at, expires_at, used_at, \
             used_by_agent_id, revoked_at FROM bootstrap_tokens ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_record()).collect()
    }

    pub async fn revoke(&self, public_id: &str) -> Result<(), RepoError> {
        let now = unix_now();
        let res = sqlx::query("UPDATE bootstrap_tokens SET revoked_at = ? WHERE public_id = ?")
            .bind(now)
            .bind(public_id)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(RepoError::AgentNotFound);
        }
        Ok(())
    }

    /// Atomic consume. Returns the bootstrap scope on success; returns
    /// `InvalidCredential` if the token doesn't exist, was used, was
    /// revoked, has expired, or the secret doesn't verify. INF-13: the
    /// caller decides whether to audit as `bootstrap_reuse_attempt` (when
    /// the token id was found but the row was already consumed) or as a
    /// generic `auth_failure`.
    pub async fn consume(
        &self,
        public_id: &str,
        secret: &SecretString,
        agent_id: i64,
    ) -> Result<BootstrapScope, RepoError> {
        let row = sqlx::query_as::<_, ConsumeRow>(
            "SELECT secret_hash, scope, expires_at, used_at, revoked_at \
             FROM bootstrap_tokens WHERE public_id = ?",
        )
        .bind(public_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(ConsumeRow {
            secret_hash,
            scope: scope_json,
            expires_at,
            used_at,
            revoked_at,
        }) = row
        else {
            return Err(RepoError::InvalidCredential);
        };
        if used_at.is_some() || revoked_at.is_some() {
            return Err(RepoError::InvalidCredential);
        }
        let now = unix_now();
        if expires_at.is_some_and(|e| e < now) {
            return Err(RepoError::InvalidCredential);
        }
        if !argon2_helper::verify(&secret_hash, secret)? {
            return Err(RepoError::InvalidCredential);
        }
        let scope: BootstrapScope = serde_json::from_str(&scope_json)?;

        // Atomic guard: only mark used if used_at is still NULL. If
        // another caller raced us, affected_rows == 0 → InvalidCredential.
        let mark_used = if scope.single_use {
            sqlx::query(
                "UPDATE bootstrap_tokens SET used_at = ?, used_by_agent_id = ? \
                 WHERE public_id = ? AND used_at IS NULL",
            )
            .bind(now)
            .bind(agent_id)
            .bind(public_id)
            .execute(&self.pool)
            .await?
        } else {
            // Reusable token: do NOT mark used_at; record last consumption agent.
            sqlx::query("UPDATE bootstrap_tokens SET used_by_agent_id = ? WHERE public_id = ?")
                .bind(agent_id)
                .bind(public_id)
                .execute(&self.pool)
                .await?
        };
        if scope.single_use && mark_used.rows_affected() == 0 {
            return Err(RepoError::InvalidCredential);
        }
        Ok(scope)
    }
}

#[derive(sqlx::FromRow)]
struct ConsumeRow {
    secret_hash: String,
    scope: String,
    expires_at: Option<i64>,
    used_at: Option<i64>,
    revoked_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct BootstrapRow {
    id: i64,
    public_id: String,
    scope: String,
    created_by: String,
    created_at: i64,
    expires_at: Option<i64>,
    used_at: Option<i64>,
    used_by_agent_id: Option<i64>,
    revoked_at: Option<i64>,
}

impl BootstrapRow {
    fn into_record(self) -> Result<BootstrapTokenRecord, RepoError> {
        Ok(BootstrapTokenRecord {
            id: self.id,
            public_id: self.public_id,
            scope: serde_json::from_str(&self.scope)?,
            created_by: self.created_by,
            created_at: self.created_at,
            expires_at: self.expires_at,
            used_at: self.used_at,
            used_by_agent_id: self.used_by_agent_id,
            revoked_at: self.revoked_at,
        })
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
