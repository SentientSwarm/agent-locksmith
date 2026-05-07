//! Registrations repository — sqlx CRUD for `registrations` and
//! `registrations_meta` tables.
//!
//! Phase E.2. See migration `migrations/0002_registrations.sql` and
//! design notes in the loop artifact (`phase-e-catalog-substrate`).
//!
//! Storage shape:
//! - `auth_json`     — [`AuthSpec`] serialized as JSON.
//! - `timeouts_json` — [`ToolTimeouts`] serialized as JSON.
//! - `metadata_json` — JSON object (per-kind freeform after locked enums).
//! - `seed`/`disabled` — i64 0/1 (SQLite has no bool).
//! - `created_at`/`updated_at` — Unix seconds (INTEGER).

use crate::config::{EgressMode, ToolTimeouts};
use crate::registrations::{AuthSpec, Kind, RegistrationError};
use serde_json::Value as Json;
use sqlx::Row;
use sqlx::SqlitePool;
use std::time::{SystemTime, UNIX_EPOCH};

/// In-memory shape of a registration row. Mirrors the DB columns plus
/// typed `auth`/`timeouts`/`metadata` fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Registration {
    pub name: String,
    pub kind: Kind,
    pub description: String,
    pub upstream: String,
    pub auth: AuthSpec,
    pub egress: EgressMode,
    pub timeouts: ToolTimeouts,
    pub body_limit_bytes: u64,
    pub metadata: Json,
    // Lifecycle:
    pub seed: bool,
    pub disabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Registration {
    /// Builder helper for tests + admin handlers — populates timestamps to
    /// "now" and lifecycle flags to operator-default (seed=false, disabled=false).
    pub fn new(
        name: String,
        kind: Kind,
        description: String,
        upstream: String,
        auth: AuthSpec,
    ) -> Self {
        let now = unix_now();
        Self {
            name,
            kind,
            description,
            upstream,
            auth,
            egress: EgressMode::default(),
            timeouts: ToolTimeouts::default(),
            body_limit_bytes: 10 * 1024 * 1024,
            metadata: Json::Object(serde_json::Map::new()),
            seed: false,
            disabled: false,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Repository for the `registrations` and `registrations_meta` tables.
#[derive(Clone)]
pub struct RegistrationRepository {
    pool: SqlitePool,
}

impl RegistrationRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a new registration. Fails on PK conflict (name already
    /// taken). The caller is responsible for cross-kind reuse / reserved-name
    /// validation (run via [`crate::registrations::validate_name`] +
    /// pre-insert kind lookup).
    pub async fn create(&self, r: &Registration) -> Result<(), RegistrationError> {
        let auth_json = serde_json::to_string(&r.auth)
            .map_err(|e| RegistrationError::Backend(format!("serialize auth: {e}")))?;
        let timeouts_json = serde_json::to_string(&r.timeouts)
            .map_err(|e| RegistrationError::Backend(format!("serialize timeouts: {e}")))?;
        let metadata_json = serde_json::to_string(&r.metadata)
            .map_err(|e| RegistrationError::Backend(format!("serialize metadata: {e}")))?;

        sqlx::query(
            "INSERT INTO registrations \
             (name, kind, description, upstream, auth_json, egress, timeouts_json, \
              body_limit_bytes, metadata_json, seed, disabled, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&r.name)
        .bind(r.kind.as_str())
        .bind(&r.description)
        .bind(&r.upstream)
        .bind(&auth_json)
        .bind(egress_as_str(r.egress))
        .bind(&timeouts_json)
        .bind(r.body_limit_bytes as i64)
        .bind(&metadata_json)
        .bind(i64::from(r.seed))
        .bind(i64::from(r.disabled))
        .bind(r.created_at)
        .bind(r.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_err)?;
        Ok(())
    }

    /// Fetch by name. Returns `None` if not present.
    pub async fn get(&self, name: &str) -> Result<Option<Registration>, RegistrationError> {
        let row = sqlx::query(
            "SELECT name, kind, description, upstream, auth_json, egress, timeouts_json, \
                    body_limit_bytes, metadata_json, seed, disabled, created_at, updated_at \
             FROM registrations WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;

        row.map(row_to_registration).transpose()
    }

    /// List all registrations of a given kind (or all kinds if `kind` is
    /// `None`). Always includes disabled rows — discovery filters at a
    /// higher layer.
    pub async fn list(&self, kind: Option<Kind>) -> Result<Vec<Registration>, RegistrationError> {
        let rows = if let Some(k) = kind {
            sqlx::query(
                "SELECT name, kind, description, upstream, auth_json, egress, timeouts_json, \
                        body_limit_bytes, metadata_json, seed, disabled, created_at, updated_at \
                 FROM registrations WHERE kind = ? ORDER BY name",
            )
            .bind(k.as_str())
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT name, kind, description, upstream, auth_json, egress, timeouts_json, \
                        body_limit_bytes, metadata_json, seed, disabled, created_at, updated_at \
                 FROM registrations ORDER BY name",
            )
            .fetch_all(&self.pool)
            .await
        };

        rows.map_err(map_sqlx_err)?
            .into_iter()
            .map(row_to_registration)
            .collect()
    }

    /// Upsert (insert-or-update). Used by admin PUT and by the seed loader.
    /// Caller decides the lifecycle flags — admin PUT sets `seed=false`
    /// (operator-owned), seed loader sets `seed=true`.
    ///
    /// On existing row: updates non-immutable fields. **Immutable**: `name`
    /// (PK) and `kind` (changing kind is a wrong_kind error at the
    /// caller layer — the repo doesn't enforce, just persists what's
    /// passed).
    pub async fn upsert(&self, r: &Registration) -> Result<(), RegistrationError> {
        let auth_json = serde_json::to_string(&r.auth)
            .map_err(|e| RegistrationError::Backend(format!("serialize auth: {e}")))?;
        let timeouts_json = serde_json::to_string(&r.timeouts)
            .map_err(|e| RegistrationError::Backend(format!("serialize timeouts: {e}")))?;
        let metadata_json = serde_json::to_string(&r.metadata)
            .map_err(|e| RegistrationError::Backend(format!("serialize metadata: {e}")))?;

        sqlx::query(
            "INSERT INTO registrations \
             (name, kind, description, upstream, auth_json, egress, timeouts_json, \
              body_limit_bytes, metadata_json, seed, disabled, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(name) DO UPDATE SET \
                description = excluded.description, \
                upstream = excluded.upstream, \
                auth_json = excluded.auth_json, \
                egress = excluded.egress, \
                timeouts_json = excluded.timeouts_json, \
                body_limit_bytes = excluded.body_limit_bytes, \
                metadata_json = excluded.metadata_json, \
                seed = excluded.seed, \
                disabled = excluded.disabled, \
                updated_at = excluded.updated_at",
        )
        .bind(&r.name)
        .bind(r.kind.as_str())
        .bind(&r.description)
        .bind(&r.upstream)
        .bind(&auth_json)
        .bind(egress_as_str(r.egress))
        .bind(&timeouts_json)
        .bind(r.body_limit_bytes as i64)
        .bind(&metadata_json)
        .bind(i64::from(r.seed))
        .bind(i64::from(r.disabled))
        .bind(r.created_at)
        .bind(r.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_err)?;
        Ok(())
    }

    /// Hard delete a row. Use [`Self::set_disabled`] for seed rows.
    pub async fn delete(&self, name: &str) -> Result<bool, RegistrationError> {
        let result = sqlx::query("DELETE FROM registrations WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
        Ok(result.rows_affected() > 0)
    }

    /// Toggle the `disabled` flag without affecting other fields. Used for
    /// `DELETE /admin/<kind>/<name>` on a seed row (sets disabled=true)
    /// and `POST .../enable` (sets disabled=false).
    pub async fn set_disabled(
        &self,
        name: &str,
        disabled: bool,
    ) -> Result<bool, RegistrationError> {
        let result =
            sqlx::query("UPDATE registrations SET disabled = ?, updated_at = ? WHERE name = ?")
                .bind(i64::from(disabled))
                .bind(unix_now())
                .bind(name)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_err)?;
        Ok(result.rows_affected() > 0)
    }

    /// Read the seed catalog version recorded in `registrations_meta`.
    /// `None` if the seed loader has never run.
    pub async fn get_seed_version(&self) -> Result<Option<String>, RegistrationError> {
        let row = sqlx::query("SELECT value FROM registrations_meta WHERE key = 'seed_version'")
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_err)?;
        Ok(row.map(|r| r.get::<String, _>(0)))
    }

    /// Persist the seed catalog version after a successful load.
    pub async fn set_seed_version(&self, version: &str) -> Result<(), RegistrationError> {
        sqlx::query(
            "INSERT INTO registrations_meta (key, value) VALUES ('seed_version', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(version)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_err)?;
        Ok(())
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn row_to_registration(row: sqlx::sqlite::SqliteRow) -> Result<Registration, RegistrationError> {
    let kind_str: String = row.get(1);
    let kind = match kind_str.as_str() {
        "model" => Kind::Model,
        "tool" => Kind::Tool,
        "infra" => Kind::Infra,
        other => {
            return Err(RegistrationError::Backend(format!(
                "unexpected kind in DB: {other}"
            )));
        }
    };
    let auth_json: String = row.get(4);
    let auth: AuthSpec = serde_json::from_str(&auth_json)
        .map_err(|e| RegistrationError::Backend(format!("deserialize auth: {e}")))?;
    let egress_str: String = row.get(5);
    let egress = match egress_str.as_str() {
        "direct" => EgressMode::Direct,
        "proxied" => EgressMode::Proxied,
        other => {
            return Err(RegistrationError::Backend(format!(
                "unexpected egress in DB: {other}"
            )));
        }
    };
    let timeouts_json: String = row.get(6);
    let timeouts: ToolTimeouts = serde_json::from_str(&timeouts_json)
        .map_err(|e| RegistrationError::Backend(format!("deserialize timeouts: {e}")))?;
    let body_limit_bytes_i64: i64 = row.get(7);
    let metadata_json: String = row.get(8);
    let metadata: Json = serde_json::from_str(&metadata_json)
        .map_err(|e| RegistrationError::Backend(format!("deserialize metadata: {e}")))?;
    let seed_i64: i64 = row.get(9);
    let disabled_i64: i64 = row.get(10);

    Ok(Registration {
        name: row.get(0),
        kind,
        description: row.get(2),
        upstream: row.get(3),
        auth,
        egress,
        timeouts,
        body_limit_bytes: body_limit_bytes_i64.max(0) as u64,
        metadata,
        seed: seed_i64 != 0,
        disabled: disabled_i64 != 0,
        created_at: row.get(11),
        updated_at: row.get(12),
    })
}

fn egress_as_str(e: EgressMode) -> &'static str {
    match e {
        EgressMode::Direct => "direct",
        EgressMode::Proxied => "proxied",
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn map_sqlx_err(e: sqlx::Error) -> RegistrationError {
    RegistrationError::Backend(format!("sqlx: {e}"))
}
