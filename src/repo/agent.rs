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
    #[error("stored account binding is invalid")]
    InvalidAccountBinding,
    #[error("grant_target_invalid: select a currently configured HTTP tool or model")]
    InvalidGrantTarget,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("rng: {0}")]
    Rng(String),
}

#[derive(Debug, Clone)]
pub struct AgentRecord {
    pub id: i64,
    pub public_id: String,
    pub name: String,
    pub description: Option<String>,
    pub secret_hash: String,
    pub tool_allowlist: Option<Vec<String>>,
    pub grants_reviewed: bool,
    pub tool_denylist: Option<Vec<String>>,
    pub metadata: Option<Json>,
    pub cert_identity: Option<String>,
    pub registered_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl AgentRecord {
    pub fn effective_allowlist(&self) -> Option<Vec<String>> {
        Some(if self.grants_reviewed {
            self.tool_allowlist.clone().unwrap_or_default()
        } else {
            Vec::new()
        })
    }

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

    pub async fn validate_grants(&self, names: &[String]) -> Result<(), RepoError> {
        for name in names {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM registrations WHERE name = ? AND kind IN ('tool', 'model') AND disabled = 0)")
                .bind(name).fetch_one(&self.pool).await?;
            if !exists {
                return Err(RepoError::InvalidGrantTarget);
            }
        }
        Ok(())
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
        self.create_inner(
            name,
            description,
            allowlist,
            denylist,
            metadata,
            expires_at,
            false,
        )
        .await
    }

    pub async fn create_reviewed(
        &self,
        name: &str,
        description: Option<&str>,
        allowlist: Option<&[String]>,
        denylist: Option<&[String]>,
        metadata: Option<&Json>,
        expires_at: Option<i64>,
    ) -> Result<(String, SecretString), RepoError> {
        self.create_inner(
            name,
            description,
            allowlist,
            denylist,
            metadata,
            expires_at,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_inner(
        &self,
        name: &str,
        description: Option<&str>,
        allowlist: Option<&[String]>,
        denylist: Option<&[String]>,
        metadata: Option<&Json>,
        expires_at: Option<i64>,
        checked: bool,
    ) -> Result<(String, SecretString), RepoError> {
        let token = StructuredToken::generate(TokenNamespace::Agent);
        let secret_hash =
            argon2_helper::hash(&SecretString::from(token.secret.expose().to_string()))?;
        let allowlist_json = serde_json::to_string(allowlist.unwrap_or_default())?;
        let denylist_json = denylist
            .map(serde_json::to_string)
            .transpose()
            .map_err(RepoError::Json)?;
        let metadata_str = metadata
            .map(serde_json::to_string)
            .transpose()
            .map_err(RepoError::Json)?;
        let now = unix_now();

        let public_id = token.public_id.as_str().to_string();
        let secret = SecretString::from(token.secret.expose().to_string());

        let res = sqlx::query(
            "INSERT INTO agents \
             (public_id, name, description, secret_hash, tool_allowlist, tool_denylist, \
              metadata, registered_at, expires_at, grants_reviewed) \
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 1 \
             WHERE ? = 0 OR NOT EXISTS (SELECT 1 FROM json_each(?) n \
                 WHERE NOT EXISTS (SELECT 1 FROM registrations r WHERE r.name=n.value AND r.kind IN ('tool','model') AND r.disabled=0))",
        )
        .bind(&public_id)
        .bind(name)
        .bind(description)
        .bind(&secret_hash)
        .bind(&allowlist_json)
        .bind(denylist_json)
        .bind(metadata_str)
        .bind(now)
        .bind(expires_at)
        .bind(checked)
        .bind(&allowlist_json)
        .execute(&self.pool)
        .await;

        match res {
            Ok(result) if result.rows_affected() == 0 => Err(RepoError::InvalidGrantTarget),
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
             expires_at, revoked_at, grants_reviewed \
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
             expires_at, revoked_at, grants_reviewed \
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
             expires_at, revoked_at, grants_reviewed \
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
             expires_at, revoked_at, grants_reviewed \
             FROM agents ORDER BY registered_at DESC"
        } else {
            "SELECT id, public_id, name, description, secret_hash, tool_allowlist, \
             tool_denylist, metadata, cert_identity, registered_at, last_used_at, \
             expires_at, revoked_at, grants_reviewed \
             FROM agents WHERE revoked_at IS NULL ORDER BY registered_at DESC"
        };
        let rows = sqlx::query_as::<_, AgentRow>(sql)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(|r| r.into_record()).collect()
    }

    /// Set or clear the agent's cert_identity (M6 / T6.5). Used by
    /// `locksmith agent register --cert-identity ...` and the M6
    /// migration tooling. Operators bind a freshly-issued cert to an
    /// existing agent without rotating its bearer secret.
    pub async fn set_cert_identity(
        &self,
        public_id: &str,
        cert_identity: Option<&str>,
    ) -> Result<(), RepoError> {
        let res = sqlx::query("UPDATE agents SET cert_identity = ? WHERE public_id = ?")
            .bind(cert_identity)
            .bind(public_id)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(RepoError::AgentNotFound);
        }
        Ok(())
    }

    /// Soft-delete via `revoked_at = now`, removing the agent's account
    /// bindings, stashed backend bindings, grants and native grant sets
    /// in the same transaction (#157). Idempotent — re-revoking updates
    /// `revoked_at` to the latest call's timestamp and removes anything an
    /// earlier revoke left behind.
    pub async fn revoke(&self, public_id: &str) -> Result<StrippedAuthority, RepoError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let id: Option<i64> = sqlx::query_scalar("SELECT id FROM agents WHERE public_id = ?")
            .bind(public_id)
            .fetch_optional(&mut *tx)
            .await?;
        let id = id.ok_or(RepoError::AgentNotFound)?;
        sqlx::query("UPDATE agents SET revoked_at = ? WHERE id = ?")
            .bind(unix_now())
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let removed = authority_of(&mut tx, id).await?;
        strip_authority(&mut tx, id).await?;
        tx.commit().await?;
        Ok(removed)
    }

    /// Remove what earlier revokes left behind: bindings, stashed backend
    /// bindings, grants and native grant sets of every revoked agent.
    /// `dry_run` reports without changing anything. Agents with nothing
    /// left are omitted, so a second run returns nothing.
    pub async fn prune_revoked(&self, dry_run: bool) -> Result<Vec<PrunedAgent>, RepoError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let revoked: Vec<(i64, String, String)> = sqlx::query_as(
            "SELECT id, public_id, name FROM agents WHERE revoked_at IS NOT NULL ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await?;
        let mut pruned = Vec::new();
        for (id, public_id, name) in revoked {
            let removed = authority_of(&mut tx, id).await?;
            if removed.is_empty() {
                continue;
            }
            if !dry_run {
                strip_authority(&mut tx, id).await?;
            }
            pruned.push(PrunedAgent {
                public_id,
                name,
                removed,
            });
        }
        tx.commit().await?;
        Ok(pruned)
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
        self.update_policy_inner(public_id, allowlist, denylist, metadata, expires_at, false)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_policy_reviewed(
        &self,
        public_id: &str,
        allowlist: Option<Option<Vec<String>>>,
        denylist: Option<Option<Vec<String>>>,
        metadata: Option<Option<Json>>,
        expires_at: Option<Option<i64>>,
    ) -> Result<(), RepoError> {
        self.update_policy_inner(public_id, allowlist, denylist, metadata, expires_at, true)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_policy_inner(
        &self,
        public_id: &str,
        allowlist: Option<Option<Vec<String>>>,
        denylist: Option<Option<Vec<String>>>,
        metadata: Option<Option<Json>>,
        expires_at: Option<Option<i64>>,
        checked: bool,
    ) -> Result<(), RepoError> {
        let check_targets = checked && allowlist.is_some();
        let targets = serde_json::to_string(
            &allowlist
                .as_ref()
                .and_then(|v| v.as_ref())
                .cloned()
                .unwrap_or_default(),
        )?;
        let mut sets: Vec<&str> = Vec::new();
        let mut allowlist_str: Option<Option<String>> = None;
        let mut denylist_str: Option<Option<String>> = None;
        let mut metadata_str: Option<Option<String>> = None;
        if let Some(a) = allowlist {
            sets.push("tool_allowlist = ?");
            sets.push("grants_reviewed = 1");
            allowlist_str = Some(match a {
                Some(v) => Some(serde_json::to_string(&v)?),
                None => Some("[]".into()),
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
        let sql = format!(
            "UPDATE agents SET {} WHERE public_id = ? AND (? = 0 OR NOT EXISTS (SELECT 1 FROM json_each(?) n WHERE NOT EXISTS (SELECT 1 FROM registrations r WHERE r.name=n.value AND r.kind IN ('tool','model') AND r.disabled=0)))",
            sets.join(", ")
        );
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
        q = q.bind(public_id).bind(check_targets).bind(targets);
        let res = q.execute(&self.pool).await?;
        if res.rows_affected() == 0 {
            if check_targets && self.get_active_by_public_id(public_id).await?.is_some() {
                return Err(RepoError::InvalidGrantTarget);
            }
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
    grants_reviewed: bool,
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
            grants_reviewed: self.grants_reviewed,
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

/// What a revoke or prune removed from one agent (#157): bound routes,
/// stashed `route/backend` bindings, granted connections and native grant
/// sets. Names only, never credential values.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StrippedAuthority {
    pub bindings: Vec<String>,
    pub stashed_bindings: Vec<String>,
    pub grants: i64,
    pub native_grant_sets: i64,
}

impl StrippedAuthority {
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
            && self.stashed_bindings.is_empty()
            && self.grants == 0
            && self.native_grant_sets == 0
    }

    /// Counts only, for audit.
    pub fn counts(&self) -> Json {
        serde_json::json!({
            "bindings": self.bindings.len(),
            "stashed_bindings": self.stashed_bindings.len(),
            "grants": self.grants,
            "native_grant_sets": self.native_grant_sets,
        })
    }
}

/// A revoked agent `prune_revoked` found authority for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PrunedAgent {
    pub public_id: String,
    pub name: String,
    #[serde(flatten)]
    pub removed: StrippedAuthority,
}

async fn authority_of(
    tx: &mut sqlx::SqliteConnection,
    id: i64,
) -> Result<StrippedAuthority, RepoError> {
    let bindings = sqlx::query_scalar(
        "SELECT registration FROM agent_credential_overrides WHERE agent_id = ? \
         ORDER BY registration",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let stashed_bindings = sqlx::query_scalar(
        "SELECT route || '/' || backend FROM backend_bindings WHERE agent_id = ? ORDER BY 1",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let grants = sqlx::query_scalar(
        "SELECT CASE WHEN json_valid(tool_allowlist) \
         THEN json_array_length(tool_allowlist) ELSE 0 END FROM agents WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let native_grant_sets =
        sqlx::query_scalar("SELECT COUNT(*) FROM native_grant_sets WHERE agent_id = ?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    Ok(StrippedAuthority {
        bindings,
        stashed_bindings,
        grants,
        native_grant_sets,
    })
}

/// Remove an agent's bindings, stashes, grants and native grant sets.
/// Deleting bindings fires the native triggers that drop tool grants.
async fn strip_authority(tx: &mut sqlx::SqliteConnection, id: i64) -> Result<(), RepoError> {
    for sql in [
        "DELETE FROM agent_credential_overrides WHERE agent_id = ?",
        "DELETE FROM backend_bindings WHERE agent_id = ?",
        "DELETE FROM native_grant_sets WHERE agent_id = ?",
        "UPDATE agents SET tool_allowlist = '[]' WHERE id = ? AND tool_allowlist IS NOT '[]'",
    ] {
        sqlx::query(sql).bind(id).execute(&mut *tx).await?;
    }
    Ok(())
}
