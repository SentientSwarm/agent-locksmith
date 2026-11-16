//! `rate_limits` rows (migration 0027).

use super::Limit;
use serde::Serialize;
use sqlx::{Row, SqlitePool};

#[derive(Debug, Clone, Serialize)]
pub struct RateLimitRow {
    pub route: String,
    #[serde(skip)]
    pub agent_id: Option<i64>,
    /// The agent's public id; `None` for the route default.
    pub agent: Option<String>,
    #[serde(flatten)]
    pub limit: Limit,
    pub updated_at: i64,
}

#[derive(Clone)]
pub struct RateLimitRepository {
    pool: SqlitePool,
}

impl RateLimitRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn list(&self) -> Result<Vec<RateLimitRow>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT r.route, r.agent_id, a.public_id, r.requests_per_minute, \
             r.max_concurrent, r.updated_at \
             FROM rate_limits r LEFT JOIN agents a ON a.id = r.agent_id \
             ORDER BY r.route, r.agent_id IS NOT NULL, a.public_id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row).collect()
    }

    pub async fn get(
        &self,
        route: &str,
        agent_id: Option<i64>,
    ) -> Result<Option<Limit>, sqlx::Error> {
        let found = sqlx::query(
            "SELECT requests_per_minute, max_concurrent FROM rate_limits \
             WHERE route = ? AND agent_id IS ?",
        )
        .bind(route)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;
        found.map(|r| limit(&r)).transpose()
    }

    /// Insert or replace the limit for `(route, agent_id)`.
    pub async fn set(
        &self,
        route: &str,
        agent_id: Option<i64>,
        limit: Limit,
        now_ms: i64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM rate_limits WHERE route = ? AND agent_id IS ?")
            .bind(route)
            .bind(agent_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO rate_limits \
             (route, agent_id, requests_per_minute, max_concurrent, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(route)
        .bind(agent_id)
        .bind(i64::from(limit.requests_per_minute))
        .bind(limit.max_concurrent.map(i64::from))
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
        tx.commit().await
    }

    /// Delete the limit for `(route, agent_id)`; false when there was none.
    pub async fn delete(&self, route: &str, agent_id: Option<i64>) -> Result<bool, sqlx::Error> {
        let done = sqlx::query("DELETE FROM rate_limits WHERE route = ? AND agent_id IS ?")
            .bind(route)
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}

fn limit(r: &sqlx::sqlite::SqliteRow) -> Result<Limit, sqlx::Error> {
    let rpm: i64 = r.try_get("requests_per_minute")?;
    let concurrent: Option<i64> = r.try_get("max_concurrent")?;
    let bad = |e: std::num::TryFromIntError| sqlx::Error::Decode(Box::new(e));
    Ok(Limit {
        requests_per_minute: u32::try_from(rpm).map_err(bad)?,
        max_concurrent: concurrent.map(u32::try_from).transpose().map_err(bad)?,
    })
}

fn row(r: &sqlx::sqlite::SqliteRow) -> Result<RateLimitRow, sqlx::Error> {
    Ok(RateLimitRow {
        route: r.try_get("route")?,
        agent_id: r.try_get("agent_id")?,
        agent: r.try_get("public_id")?,
        limit: limit(r)?,
        updated_at: r.try_get("updated_at")?,
    })
}
