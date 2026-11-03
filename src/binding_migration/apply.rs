use super::{Error, REVISION, digest, inventory, now, snapshot, types::*};
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
const PREFIX: &str = "explicit_bindings/v1/plan/";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    reviewed: String,
    after: String,
}

pub(super) async fn run(
    c: &mut SqliteConnection,
    p: &Plan,
    legacy: Vec<Legacy>,
) -> Result<usize, Error> {
    let current = snapshot::load(c).await?;
    inventory::validate_selected(&current, p)?;
    if !matches!(p.format_version, 1 | 2)
        || p.legacy != legacy
        || !(p.entries.iter().any(|e| e.selected) || p.grants.iter().any(|g| g.selected))
    {
        return Err(Error::Conflict);
    }
    let key = format!("{PREFIX}{}", p.snapshot);
    if let Some(receipt) = receipt(c, &key).await? {
        if receipt.reviewed != digest(p)? || receipt.after != digest(&current)? {
            return Err(Error::Conflict);
        }
        return Ok(0);
    }
    let mut reviewed = p.clone();
    for e in &mut reviewed.entries {
        e.selected = false;
    }
    for g in &mut reviewed.grants {
        g.selected = false;
    }
    let expected = if p.format_version == 2 {
        inventory::grant_plan(&current, legacy)?
    } else {
        inventory::plan(&current, legacy)?
    };
    if reviewed != expected {
        return Err(Error::Conflict);
    }
    insert_bindings(c, p).await?;
    for grant in p.grants.iter().filter(|g| g.selected) {
        let names = serde_json::to_string(&grant.allowlist).map_err(|_| Error::Invalid)?;
        sqlx::query("UPDATE agents SET tool_allowlist = ?, grants_reviewed = 1 WHERE id = ?")
            .bind(names)
            .bind(grant.agent_id)
            .execute(&mut *c)
            .await?;
    }
    record(c, &key, &current, p).await?;
    Ok(p.entries.iter().filter(|e| e.selected).count())
}
async fn insert_bindings(c: &mut SqliteConnection, p: &Plan) -> Result<(), Error> {
    let timestamp = now();
    for row in p.entries.iter().filter(|e| e.selected) {
        let auth = serde_json::to_string(row.auth_spec.as_ref().ok_or(Error::Conflict)?)
            .map_err(|_| Error::Invalid)?;
        sqlx::query("INSERT INTO agent_credential_overrides (agent_id, registration, auth_spec, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(row.agent_id).bind(&row.registration).bind(auth).bind(timestamp).bind(timestamp).execute(&mut *c).await?;
    }
    Ok(())
}
async fn record(
    c: &mut SqliteConnection,
    key: &str,
    before: &Snapshot,
    p: &Plan,
) -> Result<(), Error> {
    let next = before.revision.checked_add(1).ok_or(Error::Conflict)?;
    sqlx::query("INSERT INTO registrations_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(REVISION).bind(next.to_string()).execute(&mut *c).await?;
    let receipt = Receipt {
        reviewed: digest(p)?,
        after: digest(&snapshot::load(c).await?)?,
    };
    let value = serde_json::to_string(&receipt).map_err(|_| Error::Invalid)?;
    sqlx::query("INSERT INTO registrations_meta (key, value) VALUES (?, ?)")
        .bind(key)
        .bind(value)
        .execute(c)
        .await?;
    Ok(())
}

async fn receipt(c: &mut SqliteConnection, key: &str) -> Result<Option<Receipt>, Error> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT value FROM registrations_meta WHERE key=?")
            .bind(key)
            .fetch_optional(c)
            .await?;
    raw.map(|s| serde_json::from_str(&s).map_err(|_| Error::Conflict))
        .transpose()
}
