//! `agent_credential_overrides` repository — Phase G.
//!
//! Explicit per-agent account selections. Each row is a complete [`AuthSpec`]
//! keyed by `(agent_id, registration)`. The authenticated proxy requires a row
//! before resolving credentials; an absent row denies access, and failed reads
//! fail closed. Several allowed agents may explicitly select the same source.
//!
//! See `agents-stack/docs/spec/v0.2.0.md` "Per-agent credential
//! overrides + OAuth session labels (Phase G)" for the full design.

use super::agent::RepoError;
use crate::registrations::AuthSpec;
use sqlx::Row;
use sqlx::SqlitePool;

/// In-memory shape of an `agent_credential_overrides` row. Returned by
/// `get` / `list_for_agent`.
#[derive(Debug, Clone)]
pub struct AgentCredentialOverride {
    pub agent_id: i64,
    pub registration: String,
    pub auth_spec: AuthSpec,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Repository for the `agent_credential_overrides` table.
#[derive(Clone)]
pub struct AgentCredentialRepository {
    pub(crate) pool: SqlitePool,
}

impl AgentCredentialRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// UPSERT an override. Operator CLI calls this via
    /// `locksmith agent set-credential <agent> <reg> ...`. Idempotent —
    /// re-running with the same args replaces the prior row's
    /// `auth_spec` and bumps `updated_at`.
    pub async fn set(
        &self,
        agent_id: i64,
        registration: &str,
        auth_spec: &AuthSpec,
    ) -> Result<(), RepoError> {
        let mut tx = self.pool.begin().await?;
        Self::set_into(&mut tx, agent_id, registration, auth_spec).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_live_bearer(
        &self,
        agent: i64,
        registration: &str,
        auth: &AuthSpec,
    ) -> Result<(), RepoError> {
        let AuthSpec::StoredBearer { secret_ref } = auth else {
            return Err(RepoError::InvalidGrantTarget);
        };
        let mut tx = self.pool.begin().await?;
        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM credential_secrets WHERE secret_ref=? AND tombstoned_at IS NULL)")
            .bind(secret_ref).fetch_one(&mut *tx).await?;
        if !live {
            return Err(RepoError::InvalidGrantTarget);
        }
        Self::set_into(&mut tx, agent, registration, auth).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn set_into(
        connection: &mut sqlx::SqliteConnection,
        agent_id: i64,
        registration: &str,
        auth_spec: &AuthSpec,
    ) -> Result<(), RepoError> {
        if matches!(auth_spec, AuthSpec::ControlledOauth { .. }) {
            return Err(RepoError::InvalidGrantTarget);
        }
        let row = sqlx::query("SELECT * FROM registrations WHERE name=?")
            .bind(registration)
            .fetch_optional(&mut *connection)
            .await?
            .ok_or(RepoError::InvalidGrantTarget)?;
        let r = crate::registrations::repo::row_to_registration(row)
            .map_err(|_| RepoError::InvalidGrantTarget)?;
        crate::definitions::eligibility::selected(connection, &r, Some(auth_spec))
            .await
            .map_err(|_| RepoError::InvalidGrantTarget)?;
        let auth_json = serde_json::to_string(auth_spec)?;
        let now = unix_now();
        let result = sqlx::query(
            "INSERT INTO agent_credential_overrides \
                (agent_id, registration, auth_spec, created_at, updated_at) \
             SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM registrations WHERE name = ? AND kind IN ('tool', 'model') AND disabled = 0) \
             ON CONFLICT(agent_id, registration) DO UPDATE SET \
                auth_spec = excluded.auth_spec, \
                updated_at = excluded.updated_at",
        )
        .bind(agent_id)
        .bind(registration)
        .bind(&auth_json)
        .bind(now)
        .bind(now)
        .bind(registration)
        .execute(connection)
        .await?;
        if result.rows_affected() == 0 {
            return Err(RepoError::InvalidGrantTarget);
        }
        Ok(())
    }

    /// Look up the override for `(agent_id, registration)`. Returns
    /// `Ok(None)` when no binding exists — the authenticated proxy denies
    /// access rather than inheriting the registration's auth_spec.
    ///
    /// This is the single hot-path call. Hits the SQLite page cache
    /// after the first request per (agent, registration) tuple, sub-ms.
    pub async fn get(
        &self,
        agent_id: i64,
        registration: &str,
    ) -> Result<Option<AgentCredentialOverride>, RepoError> {
        let row = sqlx::query(
            "SELECT agent_id, registration, auth_spec, created_at, updated_at \
             FROM agent_credential_overrides \
             WHERE agent_id = ? AND registration = ?",
        )
        .bind(agent_id)
        .bind(registration)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| row_to_override(&r)).transpose()
    }

    /// Idempotent delete. Returns `true` when a row was actually
    /// removed, `false` when no override existed for the key.
    pub async fn delete(&self, agent_id: i64, registration: &str) -> Result<bool, RepoError> {
        let res = sqlx::query(
            "DELETE FROM agent_credential_overrides \
             WHERE agent_id = ? AND registration = ?",
        )
        .bind(agent_id)
        .bind(registration)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Test-only accessor for the underlying pool. Used by FK-cascade
    /// tests that need to bypass the agent repo.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// List all overrides for a single agent. Used by
    /// `locksmith agent credentials list <agent>` for operator
    /// visibility into who's pinned to what.
    pub async fn list_for_agent(
        &self,
        agent_id: i64,
    ) -> Result<Vec<AgentCredentialOverride>, RepoError> {
        let rows = sqlx::query(
            "SELECT agent_id, registration, auth_spec, created_at, updated_at \
             FROM agent_credential_overrides \
             WHERE agent_id = ? ORDER BY registration",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_override).collect()
    }

    /// List every override across all agents. Used off the hot path by
    /// the `op://` resolver resync (Phase J / M2, T2.2) to find references
    /// that only a per-agent override uses.
    pub async fn list_all(&self) -> Result<Vec<AgentCredentialOverride>, RepoError> {
        let rows = sqlx::query(
            "SELECT agent_id, registration, auth_spec, created_at, updated_at \
             FROM agent_credential_overrides ORDER BY agent_id, registration",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_override).collect()
    }
}

fn row_to_override(row: &sqlx::sqlite::SqliteRow) -> Result<AgentCredentialOverride, RepoError> {
    let auth_json: String = row.get("auth_spec");
    let auth_spec: AuthSpec =
        serde_json::from_str(&auth_json).map_err(|_| RepoError::InvalidAccountBinding)?;
    Ok(AgentCredentialOverride {
        agent_id: row.get("agent_id"),
        registration: row.get("registration"),
        auth_spec,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::open_and_migrate;
    use crate::repo::AgentRepository;
    use tempfile::TempDir;

    async fn fresh() -> (TempDir, AgentRepository, AgentCredentialRepository) {
        let dir = TempDir::new().unwrap();
        let pool = open_and_migrate(&dir.path().join("db.sqlite"))
            .await
            .unwrap();
        let registrations = crate::registrations::RegistrationRepository::new(pool.clone());
        for name in ["lmstudio", "tavily", "codex"] {
            registrations
                .create(&crate::registrations::Registration::new(
                    name.into(),
                    crate::registrations::Kind::Tool,
                    "fixture".into(),
                    "http://127.0.0.1:1".into(),
                    AuthSpec::None,
                ))
                .await
                .unwrap();
        }
        let agents = AgentRepository::new(pool.clone());
        let creds = AgentCredentialRepository::new(pool);
        (dir, agents, creds)
    }

    async fn make_agent(agents: &AgentRepository, name: &str) -> i64 {
        agents
            .create(name, None, None, None, None, None)
            .await
            .unwrap();
        let rec = agents.get_by_name(name).await.unwrap().unwrap();
        rec.id
    }

    #[tokio::test]
    async fn set_and_get_roundtrip() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        let spec = AuthSpec::Bearer {
            env_var: "LM_STUDIO_API_KEY_HERMES".to_string(),
        };
        creds.set(id, "lmstudio", &spec).await.unwrap();
        let back = creds.get(id, "lmstudio").await.unwrap().unwrap();
        assert_eq!(back.auth_spec, spec);
        assert_eq!(back.agent_id, id);
        assert_eq!(back.registration, "lmstudio");
    }

    #[tokio::test]
    async fn get_returns_none_when_no_override() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "openclaw").await;
        assert!(creds.get(id, "lmstudio").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_is_idempotent_and_replaces_prior_value() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        creds
            .set(
                id,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "OLD".into(),
                },
            )
            .await
            .unwrap();
        creds
            .set(
                id,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "NEW".into(),
                },
            )
            .await
            .unwrap();
        let back = creds.get(id, "lmstudio").await.unwrap().unwrap();
        match back.auth_spec {
            AuthSpec::Bearer { env_var } => assert_eq!(env_var, "NEW"),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        creds
            .set(
                id,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "X".into(),
                },
            )
            .await
            .unwrap();
        assert!(creds.delete(id, "lmstudio").await.unwrap());
        assert!(creds.get(id, "lmstudio").await.unwrap().is_none());
        // second delete is fine, just returns false.
        assert!(!creds.delete(id, "lmstudio").await.unwrap());
    }

    #[tokio::test]
    async fn list_for_agent_returns_all_their_overrides() {
        let (_d, agents, creds) = fresh().await;
        let h = make_agent(&agents, "hermes").await;
        let o = make_agent(&agents, "openclaw").await;
        creds
            .set(
                h,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "LM_HERMES".into(),
                },
            )
            .await
            .unwrap();
        creds
            .set(
                h,
                "tavily",
                &AuthSpec::Bearer {
                    env_var: "TAVILY_HERMES".into(),
                },
            )
            .await
            .unwrap();
        creds
            .set(
                o,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "LM_OPENCLAW".into(),
                },
            )
            .await
            .unwrap();

        let h_overrides = creds.list_for_agent(h).await.unwrap();
        assert_eq!(h_overrides.len(), 2);
        let names: Vec<&str> = h_overrides
            .iter()
            .map(|o| o.registration.as_str())
            .collect();
        assert!(names.contains(&"lmstudio"));
        assert!(names.contains(&"tavily"));

        let o_overrides = creds.list_for_agent(o).await.unwrap();
        assert_eq!(o_overrides.len(), 1);
        assert_eq!(o_overrides[0].registration, "lmstudio");
    }

    #[tokio::test]
    async fn override_cascades_on_agent_delete() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        creds
            .set(
                id,
                "lmstudio",
                &AuthSpec::Bearer {
                    env_var: "X".into(),
                },
            )
            .await
            .unwrap();
        // Hard delete via raw SQL to exercise the FK cascade.
        sqlx::query("DELETE FROM agents WHERE id = ?")
            .bind(id)
            .execute(creds.pool())
            .await
            .unwrap();
        assert!(creds.get(id, "lmstudio").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oauth_override_with_session_label_roundtrips() {
        let (_d, agents, creds) = fresh().await;
        let id = make_agent(&agents, "hermes").await;
        let spec = AuthSpec::OauthDeviceCode {
            client_id: "x".into(),
            scopes: vec![],
            device_url: "https://d".into(),
            token_url: "https://t".into(),
            session_label: Some("hermes".into()),
        };
        creds.set(id, "codex", &spec).await.unwrap();
        let back = creds.get(id, "codex").await.unwrap().unwrap();
        assert_eq!(back.auth_spec.oauth_session_label(), Some("hermes"));
    }

    #[tokio::test]
    async fn list_all_spans_every_agent() {
        let (_d, agents, creds) = fresh().await;
        let a = make_agent(&agents, "hermes").await;
        let b = make_agent(&agents, "openclaw").await;
        let op = AuthSpec::OpBearer {
            reference: "op://v/i/f".into(),
        };
        creds.set(a, "lmstudio", &op).await.unwrap();
        creds
            .set(
                b,
                "tavily",
                &AuthSpec::Bearer {
                    env_var: "T".into(),
                },
            )
            .await
            .unwrap();
        let all = creds.list_all().await.unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|o| o.agent_id == a && o.auth_spec == op));
        assert!(
            all.iter()
                .any(|o| o.agent_id == b && o.registration == "tavily")
        );
    }
}
