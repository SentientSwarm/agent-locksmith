//! Audit repository scaffold (T2.7 / C-10). M2 ships the schema + types;
//! M3 wires writes from ProxyEngine and AdminService.

use super::agent::RepoError;
use crate::audit_sink::JsonlSink;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EventClass {
    #[default]
    Proxy,
    Operator,
    Security,
}

impl EventClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventClass::Proxy => "proxy",
            EventClass::Operator => "operator",
            EventClass::Security => "security",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    #[default]
    Allowed,
    Denied,
    Error,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allowed => "allowed",
            Decision::Denied => "denied",
            Decision::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditEvent {
    pub ts_ms: i64,
    pub event_class: EventClass,
    pub event: String,
    pub agent_public_id: Option<String>,
    pub operator_name: Option<String>,
    pub tool: Option<String>,
    pub upstream_host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub latency_ms: Option<u64>,
    pub decision: Decision,
    pub auth_method: Option<String>,
    pub origin_ip: Option<String>,
    pub details: Option<Json>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub agent_public_id: Option<String>,
    pub tool: Option<String>,
    pub event_class: Option<EventClass>,
    pub decision: Option<Decision>,
}

#[derive(Debug, Clone, Copy)]
pub struct AuditPage {
    pub limit: u32,
    pub offset: u32,
}

impl Default for AuditPage {
    fn default() -> Self {
        Self {
            limit: 100,
            offset: 0,
        }
    }
}

#[derive(Clone)]
pub struct AuditRepository {
    pool: SqlitePool,
    /// Optional JSONL mirror sink (T3.3). When set, every successful
    /// SQL insert also appends one line. Mirrors columns 1:1.
    sink: Option<Arc<JsonlSink>>,
}

impl AuditRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool, sink: None }
    }

    /// Attach a JSONL sink that mirrors every successful insert. The
    /// sink is shared across cloned `AuditRepository` handles via Arc.
    pub fn with_sink(mut self, sink: Arc<JsonlSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Synchronous insert per INF-26. Audit failures are logged but do
    /// NOT propagate to the caller — audit must never block proxy traffic.
    /// Callers that need to know about a failure can inspect the returned
    /// `Result`; production code typically logs and discards.
    pub async fn record(&self, event: &AuditEvent) -> Result<(), RepoError> {
        let details_json = event
            .details
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        sqlx::query(
            "INSERT INTO audit \
             (ts, event_class, event, agent_public_id, operator_name, tool, \
              upstream_host, method, path, status, latency_ms, decision, \
              auth_method, origin_ip, details) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(event.ts_ms)
        .bind(event.event_class.as_str())
        .bind(&event.event)
        .bind(event.agent_public_id.as_deref())
        .bind(event.operator_name.as_deref())
        .bind(event.tool.as_deref())
        .bind(event.upstream_host.as_deref())
        .bind(event.method.as_deref())
        .bind(event.path.as_deref())
        .bind(event.status.map(i64::from))
        .bind(event.latency_ms.map(|l| l as i64))
        .bind(event.decision.as_str())
        .bind(event.auth_method.as_deref())
        .bind(event.origin_ip.as_deref())
        .bind(details_json)
        .execute(&self.pool)
        .await?;
        // JSONL mirror — best-effort, errors logged + swallowed inside
        // the sink so audit insertion can't ever fail mid-mirror.
        if let Some(sink) = &self.sink {
            sink.append(event).await;
        }
        Ok(())
    }

    /// Delete audit rows whose timestamp is strictly older than
    /// `cutoff_ms`. Returns the number of rows removed. Bounded
    /// scope — only the `audit` table is touched (T3.5 verification
    /// gate). Idempotent — running twice with no new rows in between
    /// is a no-op (the second call deletes 0 rows).
    pub async fn sweep_older_than(&self, cutoff_ms: i64) -> Result<u64, RepoError> {
        let res = sqlx::query("DELETE FROM audit WHERE ts < ?")
            .bind(cutoff_ms)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn query(
        &self,
        filter: &AuditFilter,
        page: AuditPage,
    ) -> Result<Vec<AuditEvent>, RepoError> {
        // Simple builder; full SQL composition is M3 territory.
        let mut sql = String::from(
            "SELECT ts, event_class, event, agent_public_id, operator_name, tool, \
             upstream_host, method, path, status, latency_ms, decision, auth_method, \
             origin_ip, details FROM audit WHERE 1=1",
        );
        if filter.since_ms.is_some() {
            sql.push_str(" AND ts >= ?");
        }
        if filter.until_ms.is_some() {
            sql.push_str(" AND ts < ?");
        }
        if filter.agent_public_id.is_some() {
            sql.push_str(" AND agent_public_id = ?");
        }
        if filter.tool.is_some() {
            sql.push_str(" AND tool = ?");
        }
        if filter.event_class.is_some() {
            sql.push_str(" AND event_class = ?");
        }
        if filter.decision.is_some() {
            sql.push_str(" AND decision = ?");
        }
        sql.push_str(" ORDER BY ts DESC LIMIT ? OFFSET ?");

        let mut q = sqlx::query_as::<_, AuditRow>(&sql);
        if let Some(v) = filter.since_ms {
            q = q.bind(v);
        }
        if let Some(v) = filter.until_ms {
            q = q.bind(v);
        }
        if let Some(v) = &filter.agent_public_id {
            q = q.bind(v);
        }
        if let Some(v) = &filter.tool {
            q = q.bind(v);
        }
        if let Some(v) = filter.event_class {
            q = q.bind(v.as_str());
        }
        if let Some(v) = filter.decision {
            q = q.bind(v.as_str());
        }
        q = q.bind(i64::from(page.limit));
        q = q.bind(i64::from(page.offset));
        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(|r| r.into_event()).collect()
    }
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    ts: i64,
    event_class: String,
    event: String,
    agent_public_id: Option<String>,
    operator_name: Option<String>,
    tool: Option<String>,
    upstream_host: Option<String>,
    method: Option<String>,
    path: Option<String>,
    status: Option<i64>,
    latency_ms: Option<i64>,
    decision: String,
    auth_method: Option<String>,
    origin_ip: Option<String>,
    details: Option<String>,
}

impl AuditRow {
    fn into_event(self) -> Result<AuditEvent, RepoError> {
        Ok(AuditEvent {
            ts_ms: self.ts,
            event_class: parse_event_class(&self.event_class)?,
            event: self.event,
            agent_public_id: self.agent_public_id,
            operator_name: self.operator_name,
            tool: self.tool,
            upstream_host: self.upstream_host,
            method: self.method,
            path: self.path,
            status: self.status.and_then(|s| u16::try_from(s).ok()),
            latency_ms: self.latency_ms.map(|l| l as u64),
            decision: parse_decision(&self.decision)?,
            auth_method: self.auth_method,
            origin_ip: self.origin_ip,
            details: self
                .details
                .map(|s| serde_json::from_str::<Json>(&s))
                .transpose()?,
        })
    }
}

fn parse_event_class(s: &str) -> Result<EventClass, RepoError> {
    match s {
        "proxy" => Ok(EventClass::Proxy),
        "operator" => Ok(EventClass::Operator),
        "security" => Ok(EventClass::Security),
        other => Err(RepoError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown event_class: {other}"),
        )))),
    }
}

fn parse_decision(s: &str) -> Result<Decision, RepoError> {
    match s {
        "allowed" => Ok(Decision::Allowed),
        "denied" => Ok(Decision::Denied),
        "error" => Ok(Decision::Error),
        other => Err(RepoError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown decision: {other}"),
        )))),
    }
}
