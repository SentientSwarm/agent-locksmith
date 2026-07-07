//! `operational_logs` repository — Phase J / M2 (LOG-1, WEM-446).
//!
//! Structured daemon-internal operational event stream, **distinct from
//! the audit stream** (`src/repo/audit.rs`). Audit answers "which agent /
//! operator did what, and was it allowed?"; the operational log answers
//! "what did the daemon itself do — config reloads, OAuth-refresh
//! degradations, registration mutations, credential-store degradations?".
//! The two streams share nothing but a SQLite pool: separate tables,
//! separate retention, separate query routes.
//!
//! **Secret-free by contract (LOG-4).** Rows carry event names +
//! non-secret context only. A credential value must never reach an
//! `insert` — the emitter (T2.6) and query route (T2.7) are the only
//! writers/readers and neither surfaces a secret.
//!
//! `level` and `component` are validated closed sets ([`LogLevel`] /
//! [`LogComponent`]) so a typo can't create an unqueryable row and the
//! query route can `400` an invalid filter (T2.7).

use super::agent::RepoError;
use serde_json::Value as Json;
use sqlx::SqlitePool;

/// Severity of an operational-log row. Closed set — the query route
/// rejects anything else at the API boundary (T2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }

    /// Parse the wire/DB string form. `None` for an unknown level — the
    /// query route turns that into a `400`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "info" => Some(LogLevel::Info),
            "warn" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }
}

/// Emitting subsystem. Closed set (LOG-1): oauth | registry | agent |
/// proxy | config. The query route rejects anything else (T2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogComponent {
    Oauth,
    Registry,
    Agent,
    Proxy,
    Config,
}

impl LogComponent {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogComponent::Oauth => "oauth",
            LogComponent::Registry => "registry",
            LogComponent::Agent => "agent",
            LogComponent::Proxy => "proxy",
            LogComponent::Config => "config",
        }
    }

    /// Parse the wire/DB string form. `None` for an unknown component.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "oauth" => Some(LogComponent::Oauth),
            "registry" => Some(LogComponent::Registry),
            "agent" => Some(LogComponent::Agent),
            "proxy" => Some(LogComponent::Proxy),
            "config" => Some(LogComponent::Config),
            _ => None,
        }
    }
}

/// One operational-log row as read back from the store.
#[derive(Debug, Clone)]
pub struct OperationalLogRecord {
    pub id: i64,
    pub ts_ms: i64,
    pub level: String,
    pub component: String,
    pub event: String,
    pub message: String,
    pub fields: Option<Json>,
}

/// Query filter for [`OperationalLogStore::query`]. `level` / `component`
/// are pre-validated enums (the route parses + `400`s bad strings before
/// building the filter). `limit` / `offset` page the results.
#[derive(Debug, Clone)]
pub struct LogFilter {
    pub level: Option<LogLevel>,
    pub component: Option<LogComponent>,
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub limit: u32,
    pub offset: u32,
}

impl Default for LogFilter {
    fn default() -> Self {
        Self {
            level: None,
            component: None,
            since_ms: None,
            until_ms: None,
            limit: 100,
            offset: 0,
        }
    }
}

/// Repository for the `operational_logs` table.
#[derive(Clone)]
pub struct OperationalLogStore {
    pool: SqlitePool,
}

impl OperationalLogStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert one operational-log row. `fields` is optional structured
    /// non-secret context (serialized to the `fields` TEXT column).
    /// Returns the new row id. Callers must never pass a credential
    /// value in any argument (LOG-4).
    pub async fn insert(
        &self,
        level: LogLevel,
        component: LogComponent,
        event: &str,
        message: &str,
        fields: Option<&Json>,
    ) -> Result<i64, RepoError> {
        let fields_json = fields.map(serde_json::to_string).transpose()?;
        let res = sqlx::query(
            "INSERT INTO operational_logs (ts_ms, level, component, event, message, fields) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(now_ms())
        .bind(level.as_str())
        .bind(component.as_str())
        .bind(event)
        .bind(message)
        .bind(fields_json)
        .execute(&self.pool)
        .await?;
        Ok(res.last_insert_rowid())
    }

    /// Query rows newest-first, applying the filter's level / component /
    /// time-window predicates and paging by `limit` / `offset`.
    pub async fn query(&self, filter: &LogFilter) -> Result<Vec<OperationalLogRecord>, RepoError> {
        let mut sql = String::from(
            "SELECT id, ts_ms, level, component, event, message, fields \
             FROM operational_logs WHERE 1=1",
        );
        if filter.level.is_some() {
            sql.push_str(" AND level = ?");
        }
        if filter.component.is_some() {
            sql.push_str(" AND component = ?");
        }
        if filter.since_ms.is_some() {
            sql.push_str(" AND ts_ms >= ?");
        }
        if filter.until_ms.is_some() {
            sql.push_str(" AND ts_ms < ?");
        }
        sql.push_str(" ORDER BY ts_ms DESC, id DESC LIMIT ? OFFSET ?");

        let mut q = sqlx::query_as::<_, OperationalLogRow>(&sql);
        if let Some(v) = filter.level {
            q = q.bind(v.as_str());
        }
        if let Some(v) = filter.component {
            q = q.bind(v.as_str());
        }
        if let Some(v) = filter.since_ms {
            q = q.bind(v);
        }
        if let Some(v) = filter.until_ms {
            q = q.bind(v);
        }
        q = q.bind(i64::from(filter.limit));
        q = q.bind(i64::from(filter.offset));
        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(|r| r.into_record()).collect()
    }

    /// Delete rows whose timestamp is strictly older than `cutoff_ms`.
    /// Returns the number removed. Bounded scope — only the
    /// `operational_logs` table is touched (independent of audit
    /// retention). Idempotent.
    pub async fn sweep(&self, cutoff_ms: i64) -> Result<u64, RepoError> {
        let res = sqlx::query("DELETE FROM operational_logs WHERE ts_ms < ?")
            .bind(cutoff_ms)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Test-only accessor for the underlying pool.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[derive(sqlx::FromRow)]
struct OperationalLogRow {
    id: i64,
    ts_ms: i64,
    level: String,
    component: String,
    event: String,
    message: String,
    fields: Option<String>,
}

impl OperationalLogRow {
    fn into_record(self) -> Result<OperationalLogRecord, RepoError> {
        Ok(OperationalLogRecord {
            id: self.id,
            ts_ms: self.ts_ms,
            level: self.level,
            component: self.component,
            event: self.event,
            message: self.message,
            fields: self
                .fields
                .map(|s| serde_json::from_str::<Json>(&s))
                .transpose()?,
        })
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::open_and_migrate;
    use serde_json::json;
    use tempfile::TempDir;

    async fn fresh() -> (TempDir, OperationalLogStore) {
        let dir = TempDir::new().unwrap();
        let pool = open_and_migrate(&dir.path().join("db.sqlite"))
            .await
            .unwrap();
        (dir, OperationalLogStore::new(pool))
    }

    #[tokio::test]
    async fn insert_query_roundtrip() {
        let (_d, store) = fresh().await;
        let fields = json!({ "registration": "github", "action": "reload" });
        let id = store
            .insert(
                LogLevel::Info,
                LogComponent::Config,
                "config_reloaded",
                "configuration reloaded",
                Some(&fields),
            )
            .await
            .unwrap();
        assert!(id > 0);
        let rows = store.query(&LogFilter::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].level, "info");
        assert_eq!(rows[0].component, "config");
        assert_eq!(rows[0].event, "config_reloaded");
        assert_eq!(rows[0].message, "configuration reloaded");
        assert_eq!(rows[0].fields.as_ref().unwrap()["registration"], "github");
    }

    #[tokio::test]
    async fn filter_by_level_component_and_window() {
        let (_d, store) = fresh().await;
        store
            .insert(LogLevel::Info, LogComponent::Config, "a", "m", None)
            .await
            .unwrap();
        store
            .insert(LogLevel::Warn, LogComponent::Oauth, "b", "m", None)
            .await
            .unwrap();
        store
            .insert(LogLevel::Error, LogComponent::Proxy, "c", "m", None)
            .await
            .unwrap();

        // Filter by level.
        let warns = store
            .query(&LogFilter {
                level: Some(LogLevel::Warn),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(warns.len(), 1);
        assert_eq!(warns[0].event, "b");

        // Filter by component.
        let proxy = store
            .query(&LogFilter {
                component: Some(LogComponent::Proxy),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(proxy.len(), 1);
        assert_eq!(proxy[0].event, "c");

        // Window filter that excludes everything (future-only).
        let future = store
            .query(&LogFilter {
                since_ms: Some(now_ms() + 1_000_000),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert!(future.is_empty());

        // Window filter that includes everything.
        let all = store
            .query(&LogFilter {
                since_ms: Some(0),
                until_ms: Some(now_ms() + 1_000_000),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn sweep_by_cutoff_removes_old_only() {
        let (_d, store) = fresh().await;
        // Two rows inserted "now"; then manually backdate one so the
        // sweep can distinguish them.
        let old_id = store
            .insert(LogLevel::Info, LogComponent::Agent, "old", "m", None)
            .await
            .unwrap();
        store
            .insert(LogLevel::Info, LogComponent::Agent, "recent", "m", None)
            .await
            .unwrap();
        sqlx::query("UPDATE operational_logs SET ts_ms = 1000 WHERE id = ?")
            .bind(old_id)
            .execute(store.pool())
            .await
            .unwrap();

        let removed = store.sweep(2000).await.unwrap();
        assert_eq!(removed, 1, "only the backdated row is swept");
        let rows = store.query(&LogFilter::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "recent");
    }

    #[test]
    fn level_and_component_parse_roundtrip() {
        assert_eq!(LogLevel::parse("warn"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("bogus"), None);
        assert_eq!(LogComponent::parse("oauth"), Some(LogComponent::Oauth));
        assert_eq!(LogComponent::parse("bogus"), None);
        assert_eq!(LogLevel::Error.as_str(), "error");
        assert_eq!(LogComponent::Registry.as_str(), "registry");
    }
}
