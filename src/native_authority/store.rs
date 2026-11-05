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
    super::grants::invalidate_drift(c, current, manifest).await
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
