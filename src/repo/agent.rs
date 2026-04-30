//! Agent repository (T2.5 / C-8).
//! SPEC §4.2.10. Concurrency invariants per INF-9 (rotate) and INF-10
//! (concurrent register-with-same-name).

use crate::argon2_helper;
use crate::token::{StructuredToken, TokenNamespace};
use secrecy::SecretString;
use serde_json::Value as Json;
use sqlx::SqlitePool;

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("agent name conflict: {0}")]
    AgentNameConflict(String),
    #[error("rotation already in progress for agent {0}")]
    RotationInProgress(String),
    #[error("agent not found")]
    AgentNotFound,
    #[error("invalid current credential")]
    InvalidCredential,
    #[error("hash: {0}")]
    Hash(#[from] crate::argon2_helper::HashError),
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct AgentRecord {
    pub id: i64,
    pub public_id: String,
    pub name: String,
    pub description: Option<String>,
    pub secret_hash: String,
    pub tool_allowlist: Option<Vec<String>>,
    pub tool_denylist: Option<Vec<String>>,
    pub metadata: Option<Json>,
    pub cert_identity: Option<String>,
    pub registered_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl AgentRecord {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[derive(Clone)]
pub struct AgentRepository {
    pool: SqlitePool,
}

impl AgentRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create an agent. Returns the issued public_id and the cleartext
    /// secret (returned exactly once per R-N4).
    ///
    /// Concurrency: SQLite enforces UNIQUE(name); two concurrent inserts
    /// with the same name → exactly one succeeds (the other returns
    /// `AgentNameConflict`). INF-10.
    pub async fn create(
        &self,
        name: &str,
        description: Option<&str>,
        allowlist: Option<&[String]>,
        denylist: Option<&[String]>,
        metadata: Option<&Json>,
        expires_at: Option<i64>,
    ) -> Result<(String, SecretString), RepoError> {
        let token = StructuredToken::generate(TokenNamespace::Agent);
        let secret_hash =
            argon2_helper::hash(&SecretString::from(token.secret.expose().to_string()))?;
        let allowlist_json = allowlist
            .map(|v| serde_json::to_string(v))
            .transpose()
            .map_err(RepoError::Json)?;
        let denylist_json = denylist
            .map(|v| serde_json::to_string(v))
            .transpose()
            .map_err(RepoError::Json)?;
        let metadata_str = metadata
            .map(|m| serde_json::to_string(m))
            .transpose()
            .map_err(RepoError::Json)?;
        let now = unix_now();

        let public_id = token.public_id.as_str().to_string();
        let secret = SecretString::from(token.secret.expose().to_string());

        let res = sqlx::query(
            "INSERT INTO agents \
             (public_id, name, description, secret_hash, tool_allowlist, tool_denylist, \
              metadata, registered_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&public_id)
        .bind(name)
        .bind(description)
        .bind(&secret_hash)
        .bind(allowlist_json)
        .bind(denylist_json)
        .bind(metadata_str)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await;

        match res {
            Ok(_) => Ok((public_id, secret)),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(RepoError::AgentNameConflict(name.to_string()))
            }
            Err(e) => Err(RepoError::Sqlx(e)),
        }
    }

    pub async fn get_active_by_public_id(
        &self,
        public_id: &str,
    ) -> Result<Option<AgentRecord>, RepoError> {
        let row = sqlx::query_as::<_, AgentRow>(
            "SELECT id, public_id, name, description, secret_hash, tool_allowlist, \
             tool_denylist, metadata, cert_identity, registered_at, last_used_at, \
             expires_at, revoked_at \
             FROM agents WHERE public_id = ? AND revoked_at IS NULL",
        )
        .bind(public_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| r.into_record()).transpose()
    }

    pub async fn get_by_name(&self, name: &str) -> Result<Option<AgentRecord>, RepoError> {
        let row = sqlx::query_as::<_, AgentRow>(
            "SELECT id, public_id, name, description, secret_hash, tool_allowlist, \
             tool_denylist, metadata, cert_identity, registered_at, last_used_at, \
             expires_at, revoked_at \
             FROM agents WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| r.into_record()).transpose()
    }

    pub async fn get_by_cert_identity(
        &self,
        identity: &str,
    ) -> Result<Option<AgentRecord>, RepoError> {
        let row = sqlx::query_as::<_, AgentRow>(
            "SELECT id, public_id, name, description, secret_hash, tool_allowlist, \
             tool_denylist, metadata, cert_identity, registered_at, last_used_at, \
             expires_at, revoked_at \
             FROM agents WHERE cert_identity = ? AND revoked_at IS NULL",
        )
        .bind(identity)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| r.into_record()).transpose()
    }

    pub async fn list(&self, include_revoked: bool) -> Result<Vec<AgentRecord>, RepoError> {
        let sql = if include_revoked {
            "SELECT id, public_id, name, description, secret_hash, tool_allowlist, \
             tool_denylist, metadata, cert_identity, registered_at, last_used_at, \
             expires_at, revoked_at \
             FROM agents ORDER BY registered_at DESC"
        } else {
            "SELECT id, public_id, name, description, secret_hash, tool_allowlist, \
             tool_denylist, metadata, cert_identity, registered_at, last_used_at, \
             expires_at, revoked_at \
             FROM agents WHERE revoked_at IS NULL ORDER BY registered_at DESC"
        };
        let rows = sqlx::query_as::<_, AgentRow>(sql)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(|r| r.into_record()).collect()
    }

    /// Soft-delete via `revoked_at = now`. Idempotent — re-revoking a
    /// revoked agent updates `revoked_at` to the latest call's timestamp;
    /// callers who care about first-revoke ordering should check before.
    pub async fn revoke(&self, public_id: &str) -> Result<(), RepoError> {
        let now = unix_now();
        let res = sqlx::query("UPDATE agents SET revoked_at = ? WHERE public_id = ?")
            .bind(now)
            .bind(public_id)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(RepoError::AgentNotFound);
        }
        Ok(())
    }

    /// Rotate the agent's secret. INF-9: WHERE-clause CAS — first
    /// committer wins; concurrent rotate calls see `RotationInProgress`.
    pub async fn rotate(
        &self,
        public_id: &str,
        current_secret: &SecretString,
    ) -> Result<SecretString, RepoError> {
        // Fetch the current hash for verification (timing characteristics
        // are fine here — `public_id` is non-secret).
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT secret_hash FROM agents WHERE public_id = ? AND revoked_at IS NULL",
        )
        .bind(public_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some((current_hash,)) = row else {
            return Err(RepoError::InvalidCredential);
        };
        if !argon2_helper::verify(&current_hash, current_secret)? {
            return Err(RepoError::InvalidCredential);
        }

        let new_token = StructuredToken::generate(TokenNamespace::Agent);
        let new_hash =
            argon2_helper::hash(&SecretString::from(new_token.secret.expose().to_string()))?;
        let new_secret = SecretString::from(new_token.secret.expose().to_string());

        // CAS: only update if the hash hasn't changed since we read it
        // (no concurrent rotate beat us).
        let res = sqlx::query(
            "UPDATE agents SET secret_hash = ? \
             WHERE public_id = ? AND secret_hash = ? AND revoked_at IS NULL",
        )
        .bind(&new_hash)
        .bind(public_id)
        .bind(&current_hash)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(RepoError::RotationInProgress(public_id.to_string()));
        }
        Ok(new_secret)
    }

    pub async fn touch_last_used(&self, public_id: &str) -> Result<(), RepoError> {
        let now = unix_now();
        sqlx::query("UPDATE agents SET last_used_at = ? WHERE public_id = ?")
            .bind(now)
            .bind(public_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Update mutable policy fields. Pass `None` to leave a field
    /// unchanged; pass `Some(None)` (via `Some(json!(null))` for JSON
    /// fields) to clear it.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_policy(
        &self,
        public_id: &str,
        allowlist: Option<Option<Vec<String>>>,
        denylist: Option<Option<Vec<String>>>,
        metadata: Option<Option<Json>>,
        expires_at: Option<Option<i64>>,
    ) -> Result<(), RepoError> {
        let mut sets: Vec<&str> = Vec::new();
        let mut allowlist_str: Option<Option<String>> = None;
        let mut denylist_str: Option<Option<String>> = None;
        let mut metadata_str: Option<Option<String>> = None;
        if let Some(a) = allowlist {
            sets.push("tool_allowlist = ?");
            allowlist_str = Some(match a {
                Some(v) => Some(serde_json::to_string(&v)?),
                None => None,
            });
        }
        if let Some(d) = denylist {
            sets.push("tool_denylist = ?");
            denylist_str = Some(match d {
                Some(v) => Some(serde_json::to_string(&v)?),
                None => None,
            });
        }
        if let Some(m) = metadata {
            sets.push("metadata = ?");
            metadata_str = Some(match m {
                Some(v) => Some(serde_json::to_string(&v)?),
                None => None,
            });
        }
        if expires_at.is_some() {
            sets.push("expires_at = ?");
        }
        if sets.is_empty() {
            return Ok(());
        }
        let sql = format!("UPDATE agents SET {} WHERE public_id = ?", sets.join(", "));
        let mut q = sqlx::query(&sql);
        if let Some(v) = allowlist_str {
            q = q.bind(v);
        }
        if let Some(v) = denylist_str {
            q = q.bind(v);
        }
        if let Some(v) = metadata_str {
            q = q.bind(v);
        }
        if let Some(v) = expires_at {
            q = q.bind(v);
        }
        q = q.bind(public_id);
        let res = q.execute(&self.pool).await?;
        if res.rows_affected() == 0 {
            return Err(RepoError::AgentNotFound);
        }
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct AgentRow {
    id: i64,
    public_id: String,
    name: String,
    description: Option<String>,
    secret_hash: String,
    tool_allowlist: Option<String>,
    tool_denylist: Option<String>,
    metadata: Option<String>,
    cert_identity: Option<String>,
    registered_at: i64,
    last_used_at: Option<i64>,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
}

impl AgentRow {
    fn into_record(self) -> Result<AgentRecord, RepoError> {
        let tool_allowlist = self
            .tool_allowlist
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        let tool_denylist = self
            .tool_denylist
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        let metadata = self
            .metadata
            .map(|s| serde_json::from_str(&s))
            .transpose()?;
        Ok(AgentRecord {
            id: self.id,
            public_id: self.public_id,
            name: self.name,
            description: self.description,
            secret_hash: self.secret_hash,
            tool_allowlist,
            tool_denylist,
            metadata,
            cert_identity: self.cert_identity,
            registered_at: self.registered_at,
            last_used_at: self.last_used_at,
            expires_at: self.expires_at,
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
