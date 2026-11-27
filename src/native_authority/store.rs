use super::{Error, Result, source::Current};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub async fn token(c: &mut SqliteConnection) -> Result<String> {
    Ok(sqlx::query_scalar("SELECT lower(hex(randomblob(16)))")
        .fetch_one(c)
        .await?)
}
pub async fn observation(c: &mut SqliteConnection, current: &Current, run: &str) -> Result<Value> {
    let s = &current.source;
    let row = sqlx::query("SELECT * FROM native_observations WHERE instance=? AND account_key=?")
        .bind(&s.instance)
        .bind(&s.account_key)
        .fetch_optional(c)
        .await?;
    let Some(row) = row else {
        return Ok(Value::Null);
    };
    let fresh = row.get::<String, _>("status") == "ready"
        && row.get::<String, _>("run_id") == run
        && row.get::<i64, _>("registration_revision") == s.revision
        && row
            .get::<Option<i64>, _>("observed_at")
            .is_some_and(|t| t <= now() && now() - t < 60);
    let manifest = row
        .get::<Option<String>, _>("manifest")
        .map(|v| serde_json::from_str::<Value>(&v))
        .transpose()
        .map_err(|_| Error("backend_unavailable"))?;
    Ok(
        json!({"generation":row.get::<String,_>("generation"),"status":row.get::<String,_>("status"),
        "fresh":fresh,"observed_at":row.get::<Option<i64>,_>("observed_at"),"manifest":manifest}),
    )
}
pub async fn ready(
    c: &mut SqliteConnection,
    current: &Current,
    run: &str,
    generation: &str,
) -> Result<Value> {
    let value = observation(c, current, run).await?;
    if value["fresh"] != true || value["generation"] != generation {
        return Err(Error("observation_conflict"));
    }
    Ok(value["manifest"].clone())
}
pub async fn revision(c: &mut SqliteConnection, current: &Current) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar(
            "SELECT revision FROM native_grant_sets WHERE agent_id=? AND instance=?",
        )
        .bind(current.agent)
        .bind(&current.source.instance)
        .fetch_optional(c)
        .await?,
    )
}
pub async fn reserve(
    c: &mut SqliteConnection,
    current: &Current,
    run: &str,
    expected: Option<&str>,
) -> Result<String> {
    let old = observation(c, current, run).await?;
    if old["generation"].as_str() != expected {
        return Err(Error("observation_conflict"));
    }
    let generation = token(c).await?;
    sqlx::query("INSERT INTO native_observations(instance,account_key,generation,status,run_id,registration_revision) VALUES(?,?,?,'pending',?,?) ON CONFLICT(instance,account_key) DO UPDATE SET generation=excluded.generation,status='pending',run_id=excluded.run_id,registration_revision=excluded.registration_revision,observed_at=NULL,manifest=NULL")
        .bind(&current.source.instance).bind(&current.source.account_key).bind(&generation)
        .bind(run).bind(current.source.revision).execute(c).await?;
    Ok(generation)
}
pub async fn publish(
    c: &mut SqliteConnection,
    current: &Current,
    generation: &str,
    manifest: &Value,
) -> Result<()> {
    let bytes = serde_json::to_string(manifest).map_err(|_| Error("manifest_invalid"))?;
    let s = &current.source;
    let result = sqlx::query("UPDATE native_observations SET status='ready',observed_at=?,manifest=? WHERE instance=? AND account_key=? AND generation=? AND registration_revision=? AND status='pending'")
        .bind(now()).bind(bytes).bind(&s.instance).bind(&s.account_key).bind(generation).bind(s.revision)
        .execute(&mut *c).await?;
    if result.rows_affected() != 1 {
        return Err(Error("observation_conflict"));
    }
    super::grants::invalidate_drift(c, current, manifest).await?;
    Ok(())
}
pub async fn failed(
    c: &mut SqliteConnection,
    source: &super::source::Source,
    generation: &str,
) -> Result<()> {
    sqlx::query("UPDATE native_observations SET status='failed' WHERE instance=? AND account_key=? AND generation=? AND status='pending'")
        .bind(&source.instance).bind(&source.account_key).bind(generation).execute(c).await?;
    Ok(())
}

/// AGENT-378: refresh ahead of the 60 s boundary by at most one request budget.
pub const REFRESH_AFTER: i64 = 50;
/// A stale observation that an agent's own request may refresh.
pub struct Candidate {
    pub generation: String,
    pub manifest: Value,
    pub observed_at: i64,
    pub same_run: bool,
}
pub enum Renewal {
    Unchanged,
    Changed { invalidated: usize },
}
/// Only a ready, current-revision row the agent holds grants against. Pending,
/// failed or absent rows and registration changes stay the operator's.
pub async fn candidate(
    c: &mut SqliteConnection,
    current: &Current,
    run: &str,
    agent_id: i64,
) -> Result<Option<Candidate>> {
    let s = &current.source;
    let row = sqlx::query("SELECT o.generation,o.manifest,o.observed_at,o.run_id FROM native_observations o WHERE o.instance=? AND o.account_key=? AND o.status='ready' AND o.registration_revision=? AND o.manifest IS NOT NULL AND o.observed_at IS NOT NULL AND EXISTS(SELECT 1 FROM native_tool_grants g WHERE g.agent_id=? AND g.instance=o.instance AND g.account_key=o.account_key)")
        .bind(&s.instance).bind(&s.account_key).bind(s.revision).bind(agent_id)
        .fetch_optional(&mut *c).await?;
    let Some(row) = row else { return Ok(None) };
    let observed_at: i64 = row.get("observed_at");
    let same_run = row.get::<String, _>("run_id") == run;
    if same_run && now() - observed_at < REFRESH_AFTER && observed_at <= now() {
        return Ok(None);
    }
    let manifest = serde_json::from_str(row.get::<&str, _>("manifest"))
        .map_err(|_| Error("backend_unavailable"))?;
    Ok(Some(Candidate {
        generation: row.get("generation"),
        manifest,
        observed_at,
        same_run,
    }))
}
/// Publish a refreshed manifest without passing the row through pending.
/// Unchanged keeps the generation; changed mints one and drops drifted grants.
pub async fn renew(
    c: &mut SqliteConnection,
    current: &Current,
    run: &str,
    generation: &str,
    manifest: &Value,
) -> Result<Renewal> {
    let s = &current.source;
    let stored: Option<String> = sqlx::query_scalar("SELECT manifest FROM native_observations WHERE instance=? AND account_key=? AND generation=? AND registration_revision=? AND status='ready'")
        .bind(&s.instance).bind(&s.account_key).bind(generation).bind(s.revision)
        .fetch_optional(&mut *c).await?.flatten();
    let stored = stored.ok_or(Error("observation_conflict"))?;
    let unchanged = serde_json::from_str::<Value>(&stored).is_ok_and(|v| &v == manifest);
    let next = if unchanged {
        generation.to_owned()
    } else {
        token(c).await?
    };
    let bytes = serde_json::to_string(manifest).map_err(|_| Error("manifest_invalid"))?;
    let result = sqlx::query("UPDATE native_observations SET generation=?,manifest=?,observed_at=?,run_id=? WHERE instance=? AND account_key=? AND generation=? AND registration_revision=? AND status='ready'")
        .bind(&next).bind(bytes).bind(now()).bind(run)
        .bind(&s.instance).bind(&s.account_key).bind(generation).bind(s.revision)
        .execute(&mut *c).await?;
    if result.rows_affected() != 1 {
        return Err(Error("observation_conflict"));
    }
    if unchanged {
        return Ok(Renewal::Unchanged);
    }
    let invalidated = super::grants::invalidate_drift(c, current, manifest).await?;
    Ok(Renewal::Changed { invalidated })
}
