use super::{Error, Result, contract, protected, source::Current, store, writes::Review};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub contract_digest: String,
}
pub async fn entries(c: &mut SqliteConnection, current: &Current) -> Result<Vec<Entry>> {
    let rows = sqlx::query("SELECT name,contract_digest FROM native_tool_grants WHERE agent_id=? AND instance=? ORDER BY name")
        .bind(current.agent).bind(&current.source.instance).fetch_all(c).await?;
    Ok(rows
        .into_iter()
        .map(|r| Entry {
            name: r.get("name"),
            contract_digest: r.get("contract_digest"),
        })
        .collect())
}
pub fn observed<'a>(manifest: &'a Value, name: &str) -> Result<&'a Value> {
    manifest["tools"]
        .as_array()
        .ok_or(Error("manifest_invalid"))?
        .iter()
        .find(|v| v["tool"]["name"] == name)
        .ok_or(Error("tool_not_observed"))
}
pub async fn review(
    c: &mut SqliteConnection,
    current: &Current,
    manifest: &Value,
    input: &Review,
    secret: Option<&str>,
) -> Result<Value> {
    let name = &input.name;
    let expected = &input.observed_digest;
    let entry = observed(manifest, name)?;
    if entry["observed_digest"] != *expected {
        return Err(Error("observation_conflict"));
    }
    let value = protected::create(&entry["tool"], &input.effect, &input.context)?;
    if let Some(secret) = secret {
        contract::screen(&value, secret).map_err(|_| Error("context_secret"))?;
    }
    let response = protected::response(value)?;
    let digest = response["contract_digest"].as_str().unwrap();
    sqlx::query("INSERT INTO native_reviews(instance,account_key,name,contract_digest,observed_digest,contract) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING")
        .bind(&current.source.instance).bind(&current.source.account_key).bind(name).bind(digest)
        .bind(expected).bind(response["contract"].to_string()).execute(c).await?;
    Ok(response)
}
pub async fn replace(
    c: &mut SqliteConnection,
    current: &Current,
    manifest: &Value,
    expected: Option<&str>,
    entries: &[Entry],
) -> Result<String> {
    if store::revision(c, current).await?.as_deref() != expected {
        return Err(Error("grant_conflict"));
    }
    validate(c, current, manifest, entries).await?;
    let revision = store::token(c).await?;
    sqlx::query("INSERT INTO native_grant_sets(agent_id,instance,revision) VALUES(?,?,?) ON CONFLICT(agent_id,instance) DO UPDATE SET revision=excluded.revision")
        .bind(current.agent).bind(&current.source.instance).bind(&revision).execute(&mut *c).await?;
    sqlx::query("DELETE FROM native_tool_grants WHERE agent_id=? AND instance=?")
        .bind(current.agent)
        .bind(&current.source.instance)
        .execute(&mut *c)
        .await?;
    for entry in entries {
        sqlx::query("INSERT INTO native_tool_grants(agent_id,instance,account_key,name,contract_digest) VALUES(?,?,?,?,?)")
            .bind(current.agent).bind(&current.source.instance).bind(&current.source.account_key)
            .bind(&entry.name).bind(&entry.contract_digest).execute(&mut *c).await?;
    }
    Ok(revision)
}
async fn validate(
    c: &mut SqliteConnection,
    current: &Current,
    manifest: &Value,
    entries: &[Entry],
) -> Result<()> {
    if entries.len() > 32 {
        return Err(Error("grant_limit"));
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        if !seen.insert(&entry.name) {
            return Err(Error("duplicate_tool"));
        }
        let observed = observed(manifest, &entry.name)?;
        let row = sqlx::query("SELECT observed_digest,contract FROM native_reviews WHERE instance=? AND account_key=? AND name=? AND contract_digest=?")
            .bind(&current.source.instance).bind(&current.source.account_key).bind(&entry.name)
            .bind(&entry.contract_digest).fetch_optional(&mut *c).await?.ok_or(Error("review_required"))?;
        let value = crate::native::json::parse(row.get::<&str, _>("contract").as_bytes())
            .map_err(|_| Error("review_invalid"))?;
        protected::load(&value)?;
        if row.get::<String, _>("observed_digest") != observed["observed_digest"]
            || value["tool"] != observed["tool"]
            || contract::digest("locksmith-native-contract-v1", &value) != entry.contract_digest
        {
            return Err(Error("review_required"));
        }
    }
    Ok(())
}
pub async fn invalidate_drift(
    c: &mut SqliteConnection,
    current: &Current,
    manifest: &Value,
) -> Result<()> {
    let rows = sqlx::query("SELECT g.agent_id,g.name,g.contract_digest,r.observed_digest FROM native_tool_grants g JOIN native_reviews r USING(instance,account_key,name,contract_digest) WHERE g.instance=? AND g.account_key=?")
        .bind(&current.source.instance).bind(&current.source.account_key).fetch_all(&mut *c).await?;
    for row in rows {
        let name: String = row.get("name");
        let old: String = row.get("observed_digest");
        if observed(manifest, &name).is_ok_and(|v| v["observed_digest"] == old) {
            continue;
        }
        let agent: i64 = row.get("agent_id");
        sqlx::query("DELETE FROM native_tool_grants WHERE agent_id=? AND instance=? AND name=?")
            .bind(agent)
            .bind(&current.source.instance)
            .bind(name)
            .execute(&mut *c)
            .await?;
        sqlx::query("UPDATE native_grant_sets SET revision=lower(hex(randomblob(16))) WHERE agent_id=? AND instance=?")
            .bind(agent).bind(&current.source.instance).execute(&mut *c).await?;
    }
    Ok(())
}
