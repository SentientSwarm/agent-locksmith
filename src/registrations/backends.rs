//! Brokered routes phase 2 — declared backends for an HTTP route.
//!
//! The `registrations` row holds the ACTIVE backend's destination and auth
//! template, so admission (D4), the proxy and the catalog are unchanged.
//! `registration_backends` stores declared backends and `backend_bindings`
//! stashes per-agent bindings for backends that are not active. See
//! migration 0025 and `docs/design/2026-11-11-brokered-routes.md` §1.

use sqlx::{Row, SqlitePool};

use crate::config::EgressMode;
use crate::registrations::AuthSpec;

/// Name of the implicit backend a route has before its first switch
/// (`registrations.active_backend IS NULL`).
pub const PRIMARY: &str = "primary";

/// A declared destination for an HTTP route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteBackend {
    pub route: String,
    pub name: String,
    pub upstream: String,
    pub egress: EgressMode,
    pub upstream_ca_pem: Option<String>,
    /// Auth template copied onto the route when this backend becomes
    /// active (header name / env var / stored-credential shape).
    pub auth: AuthSpec,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("backend not found")]
    NotFound,
    #[error("backend is the route's active backend")]
    ActiveBackend,
    #[error("route cannot switch backends")]
    RouteNotSwitchable,
    #[error("backend auth is not supported for switching")]
    AuthUnsupported,
    #[error("route revision changed")]
    RevisionConflict,
    #[error("serialize: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
}

pub(crate) fn egress_str(e: EgressMode) -> &'static str {
    match e {
        EgressMode::Direct => "direct",
        EgressMode::Proxied => "proxied",
    }
}

fn parse_egress(s: &str) -> Result<EgressMode, BackendError> {
    match s {
        "direct" => Ok(EgressMode::Direct),
        "proxied" => Ok(EgressMode::Proxied),
        _ => Err(BackendError::Db(sqlx::Error::Decode(
            format!("unexpected egress {s}").into(),
        ))),
    }
}

fn row_to_backend(row: &sqlx::sqlite::SqliteRow) -> Result<RouteBackend, BackendError> {
    Ok(RouteBackend {
        route: row.get("route"),
        name: row.get("name"),
        upstream: row.get("upstream"),
        egress: parse_egress(row.get::<&str, _>("egress"))?,
        upstream_ca_pem: row.get("upstream_ca_pem"),
        auth: serde_json::from_str(row.get::<&str, _>("auth_json"))?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

const COLUMNS: &str =
    "route, name, upstream, egress, upstream_ca_pem, auth_json, created_at, updated_at";

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct BackendRepository {
    pool: SqlitePool,
}

/// A backend edit changes what a switch would activate, so it moves the
/// route's `If-Match` revision: a switch prepared against the old
/// definition gets `revision_conflict` instead of an unreviewed host.
async fn bump_revision(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    route: &str,
) -> Result<(), BackendError> {
    sqlx::query("UPDATE registration_instances SET revision = revision + 1 WHERE name = ?")
        .bind(route)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl BackendRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create or replace a declared backend. Moving its destination clears
    /// its stashed bindings (trigger `backend_destination_changed_stash`).
    pub async fn put(&self, b: &RouteBackend) -> Result<(), BackendError> {
        let now = unix_now();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(&format!(
            "INSERT INTO registration_backends ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(route, name) DO UPDATE SET upstream = excluded.upstream, \
             egress = excluded.egress, upstream_ca_pem = excluded.upstream_ca_pem, \
             auth_json = excluded.auth_json, updated_at = excluded.updated_at"
        ))
        .bind(&b.route)
        .bind(&b.name)
        .bind(&b.upstream)
        .bind(egress_str(b.egress))
        .bind(&b.upstream_ca_pem)
        .bind(serde_json::to_string(&b.auth)?)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        bump_revision(&mut tx, &b.route).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn get(&self, route: &str, name: &str) -> Result<Option<RouteBackend>, BackendError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM registration_backends WHERE route = ? AND name = ?"
        ))
        .bind(route)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| row_to_backend(&r))
        .transpose()
    }

    pub async fn list(&self, route: &str) -> Result<Vec<RouteBackend>, BackendError> {
        sqlx::query(&format!(
            "SELECT {COLUMNS} FROM registration_backends WHERE route = ? ORDER BY name"
        ))
        .bind(route)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(row_to_backend)
        .collect()
    }

    pub async fn delete(&self, route: &str, name: &str) -> Result<bool, BackendError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let r = sqlx::query("DELETE FROM registration_backends WHERE route = ? AND name = ?")
            .bind(route)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        if r.rows_affected() == 0 {
            return Ok(false);
        }
        bump_revision(&mut tx, route).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// The route's current `registration_instances.revision` (the
    /// `If-Match` token for a switch).
    pub async fn revision(&self, route: &str) -> Result<i64, BackendError> {
        sqlx::query_scalar("SELECT revision FROM registration_instances WHERE name = ?")
            .bind(route)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(BackendError::NotFound)
    }

    /// The route's active backend name (`primary` before any switch).
    pub async fn active_backend(&self, route: &str) -> Result<String, BackendError> {
        let v: Option<Option<String>> =
            sqlx::query_scalar("SELECT active_backend FROM registrations WHERE name = ?")
                .bind(route)
                .fetch_optional(&self.pool)
                .await?;
        match v {
            None => Err(BackendError::NotFound),
            Some(a) => Ok(a.unwrap_or_else(|| PRIMARY.to_string())),
        }
    }
}

/// Result of [`BackendRepository::switch`]. Carries no credential material.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SwitchOutcome {
    pub route: String,
    pub from: String,
    pub to: String,
    pub bindings_stashed: u32,
    pub bindings_restored: u32,
    pub revision: i64,
}

fn switchable_auth(a: &AuthSpec) -> bool {
    !matches!(
        a,
        AuthSpec::OauthPkce { .. }
            | AuthSpec::OauthDeviceCode { .. }
            | AuthSpec::ControlledOauth { .. }
    )
}

impl BackendRepository {
    /// Make `target` the route's active backend in one transaction.
    ///
    /// The current destination is recorded as a backend, the route's
    /// bindings are stashed under it, the target's destination is written
    /// onto the route under a `route_switch_guard` row (so the 0009/0023
    /// authority triggers keep grants), and the target's stashed bindings
    /// are restored. Stored-credential bindings whose sealed value is gone
    /// are not restored. Grants are never touched.
    pub async fn switch(
        &self,
        route: &str,
        target: &str,
        expected_revision: i64,
    ) -> Result<SwitchOutcome, BackendError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(
            "SELECT r.kind, r.protocol, r.mcp_json, r.upstream, r.egress, r.upstream_ca_pem, \
                    r.auth_json, r.active_backend, i.revision \
               FROM registrations r JOIN registration_instances i ON i.name = r.name \
              WHERE r.name = ?",
        )
        .bind(route)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(BackendError::NotFound)?;
        if row.get::<i64, _>("revision") != expected_revision {
            return Err(BackendError::RevisionConflict);
        }
        let kind: String = row.get("kind");
        let protocol: String = row.get("protocol");
        let mcp: Option<String> = row.get("mcp_json");
        if !matches!(kind.as_str(), "tool" | "model") || protocol != "http" || mcp.is_some() {
            return Err(BackendError::RouteNotSwitchable);
        }
        let auth_json: String = row.get("auth_json");
        let current_auth: AuthSpec = serde_json::from_str(&auth_json)?;
        let from = row
            .get::<Option<String>, _>("active_backend")
            .unwrap_or_else(|| PRIMARY.to_string());
        if from == target {
            return Err(BackendError::ActiveBackend);
        }
        let t = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM registration_backends WHERE route = ? AND name = ?"
        ))
        .bind(route)
        .bind(target)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(BackendError::NotFound)?;
        let t = row_to_backend(&t)?;
        if !switchable_auth(&current_auth) || !switchable_auth(&t.auth) {
            return Err(BackendError::AuthUnsupported);
        }
        let now = unix_now();

        // 1. Record the current destination as backend `from`.
        sqlx::query(&format!(
            "INSERT INTO registration_backends ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(route, name) DO UPDATE SET upstream = excluded.upstream, \
             egress = excluded.egress, upstream_ca_pem = excluded.upstream_ca_pem, \
             auth_json = excluded.auth_json, updated_at = excluded.updated_at"
        ))
        .bind(route)
        .bind(&from)
        .bind(row.get::<String, _>("upstream"))
        .bind(row.get::<String, _>("egress"))
        .bind(row.get::<Option<String>, _>("upstream_ca_pem"))
        .bind(&auth_json)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        // 2. Stash the route's bindings under `from`.
        let stashed = sqlx::query(
            "INSERT OR REPLACE INTO backend_bindings \
             (agent_id, route, backend, auth_spec, created_at, updated_at) \
             SELECT agent_id, registration, ?, auth_spec, created_at, ? \
               FROM agent_credential_overrides WHERE registration = ?",
        )
        .bind(&from)
        .bind(now)
        .bind(route)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        sqlx::query("DELETE FROM agent_credential_overrides WHERE registration = ?")
            .bind(route)
            .execute(&mut *tx)
            .await?;

        // 3. Write the target destination under the guard.
        sqlx::query(
            "INSERT INTO route_switch_guard (route, upstream, egress, upstream_ca_pem) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(route)
        .bind(&t.upstream)
        .bind(egress_str(t.egress))
        .bind(&t.upstream_ca_pem)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE registrations SET upstream = ?, egress = ?, upstream_ca_pem = ?, \
             auth_json = ?, active_backend = ?, seed = 0, updated_at = ? WHERE name = ?",
        )
        .bind(&t.upstream)
        .bind(egress_str(t.egress))
        .bind(&t.upstream_ca_pem)
        .bind(serde_json::to_string(&t.auth)?)
        .bind(target)
        .bind(now)
        .bind(route)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM route_switch_guard WHERE route = ?")
            .bind(route)
            .execute(&mut *tx)
            .await?;

        // 4. Restore the target's stashed bindings whose sealed value
        //    (if any) is still live; drop the rest of its stash.
        let restored = sqlx::query(
            "INSERT INTO agent_credential_overrides \
             (agent_id, registration, auth_spec, created_at, updated_at) \
             SELECT b.agent_id, b.route, b.auth_spec, b.created_at, ? \
               FROM backend_bindings b \
              WHERE b.route = ? AND b.backend = ? \
                AND (json_extract(b.auth_spec, '$.secret_ref') IS NULL \
                     OR EXISTS (SELECT 1 FROM credential_secrets c \
                                 WHERE c.secret_ref = json_extract(b.auth_spec, '$.secret_ref') \
                                   AND c.tombstoned_at IS NULL))",
        )
        .bind(now)
        .bind(route)
        .bind(target)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        sqlx::query("DELETE FROM backend_bindings WHERE route = ? AND backend = ?")
            .bind(route)
            .bind(target)
            .execute(&mut *tx)
            .await?;

        let revision: i64 =
            sqlx::query_scalar("SELECT revision FROM registration_instances WHERE name = ?")
                .bind(route)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(SwitchOutcome {
            route: route.to_string(),
            from,
            to: target.to_string(),
            bindings_stashed: stashed as u32,
            bindings_restored: restored as u32,
            revision,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrations::{Kind, Registration, RegistrationRepository};

    async fn pool() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::TempDir::new().unwrap();
        let pool = crate::migrations::open_and_migrate(&dir.path().join("l.db"))
            .await
            .unwrap();
        (dir, pool)
    }

    async fn route(pool: &SqlitePool, name: &str, upstream: &str) {
        RegistrationRepository::new(pool.clone())
            .create(&Registration::new(
                name.into(),
                Kind::Tool,
                String::new(),
                upstream.into(),
                AuthSpec::None,
            ))
            .await
            .unwrap();
    }

    /// A reviewed agent granted `route`, with a None binding on it.
    async fn granted_bound_agent(pool: &SqlitePool, route: &str) -> i64 {
        let agents = crate::repo::AgentRepository::new(pool.clone());
        let (pid, _) = agents
            .create("a1", None, Some(&[route.to_string()]), None, None, None)
            .await
            .unwrap();
        let id: i64 = sqlx::query_scalar("SELECT id FROM agents WHERE public_id = ?")
            .bind(&pid)
            .fetch_one(pool)
            .await
            .unwrap();
        crate::repo::AgentCredentialRepository::new(pool.clone())
            .set(id, route, &AuthSpec::None)
            .await
            .unwrap();
        id
    }

    async fn allowlisted(pool: &SqlitePool, id: i64, route: &str) -> bool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM agents, json_each(agents.tool_allowlist) \
             WHERE agents.id = ? AND value = ?",
        )
        .bind(id)
        .bind(route)
        .fetch_one(pool)
        .await
        .unwrap()
            == 1
    }

    async fn bound(pool: &SqlitePool, id: i64, route: &str) -> bool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM agent_credential_overrides \
             WHERE agent_id = ? AND registration = ?",
        )
        .bind(id)
        .bind(route)
        .fetch_one(pool)
        .await
        .unwrap()
            == 1
    }

    fn backend(route: &str, name: &str, upstream: &str) -> RouteBackend {
        RouteBackend {
            route: route.into(),
            name: name.into(),
            upstream: upstream.into(),
            egress: EgressMode::Direct,
            upstream_ca_pem: None,
            auth: AuthSpec::None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn backend_put_get_list_delete_round_trip() {
        let (_d, pool) = pool().await;
        route(&pool, "r", "https://a.example").await;
        let repo = BackendRepository::new(pool.clone());
        repo.put(&backend("r", "broker", "https://b.example"))
            .await
            .unwrap();
        repo.put(&backend("r", "alt", "https://c.example"))
            .await
            .unwrap();
        let got = repo.get("r", "broker").await.unwrap().unwrap();
        assert_eq!(got.upstream, "https://b.example");
        assert!(got.created_at > 0);
        let names: Vec<_> = repo
            .list("r")
            .await
            .unwrap()
            .into_iter()
            .map(|b| b.name)
            .collect();
        assert_eq!(names, ["alt", "broker"]);
        assert!(repo.delete("r", "alt").await.unwrap());
        assert!(!repo.delete("r", "alt").await.unwrap());
        assert!(repo.get("r", "alt").await.unwrap().is_none());
        // A backend needs its route.
        assert!(
            repo.put(&backend("missing", "b", "https://b.example"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn editing_backend_destination_clears_its_stash() {
        let (_d, pool) = pool().await;
        route(&pool, "r", "https://a.example").await;
        let id = granted_bound_agent(&pool, "r").await;
        let repo = BackendRepository::new(pool.clone());
        repo.put(&backend("r", "broker", "https://b.example"))
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO backend_bindings (agent_id, route, backend, auth_spec, created_at, updated_at) \
             VALUES (?, 'r', 'broker', '{\"kind\":\"none\"}', 1, 1)",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        let stash = || async {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM backend_bindings")
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        // Re-putting the same destination keeps the stash.
        repo.put(&backend("r", "broker", "https://b.example"))
            .await
            .unwrap();
        assert_eq!(stash().await, 1);
        repo.put(&backend("r", "broker", "https://moved.example"))
            .await
            .unwrap();
        assert_eq!(stash().await, 0);
    }

    #[tokio::test]
    async fn guard_bypasses_authority_trigger_only_on_exact_match() {
        let (_d, pool) = pool().await;
        route(&pool, "r", "https://a.example").await;
        let id = granted_bound_agent(&pool, "r").await;
        let update = |up: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query("UPDATE registrations SET upstream = ? WHERE name = 'r'")
                    .bind(up)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        };
        sqlx::query(
            "INSERT INTO route_switch_guard (route, upstream, egress, upstream_ca_pem) \
             VALUES ('r', 'https://b.example', 'direct', NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        update("https://b.example").await;
        assert!(
            allowlisted(&pool, id, "r").await,
            "guarded switch kept the grant"
        );
        assert!(
            bound(&pool, id, "r").await,
            "guarded switch kept the binding"
        );
        // A guard for a different target does not cover this update.
        update("https://c.example").await;
        assert!(!allowlisted(&pool, id, "r").await);
        assert!(!bound(&pool, id, "r").await);
    }

    #[tokio::test]
    async fn migration_24_db_reads_active_backend_null() {
        let (_d, pool) = pool().await;
        route(&pool, "r", "https://a.example").await;
        let repo = BackendRepository::new(pool.clone());
        assert_eq!(repo.active_backend("r").await.unwrap(), PRIMARY);
        assert!(repo.list("r").await.unwrap().is_empty());
    }
}
