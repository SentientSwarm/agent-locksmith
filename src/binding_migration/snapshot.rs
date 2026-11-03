//! Deliberate column projection: never query hashes, ciphertext or credential values.
use super::{Error, REVISION, types::*};
use sqlx::{Row, SqliteConnection};

pub(super) async fn load(c: &mut SqliteConnection) -> Result<Snapshot, Error> {
    Ok(Snapshot {
        agents: agents(c).await?,
        registrations: registrations(c).await?,
        bindings: bindings(c).await?,
        stored: stored(c).await?,
        sessions: sessions(c).await?,
        revision: revision(c).await?,
    })
}
async fn agents(c: &mut SqliteConnection) -> Result<Vec<Agent>, Error> {
    let rows = sqlx::query("SELECT id, public_id, name, tool_allowlist, tool_denylist, cert_identity, registered_at, expires_at, revoked_at FROM agents ORDER BY id").fetch_all(c).await?;
    rows.iter()
        .map(|r| {
            Ok(Agent {
                id: r.try_get("id")?,
                public_id: r.try_get("public_id")?,
                name: r.try_get("name")?,
                tool_allowlist: acl(r.try_get("tool_allowlist")?)?,
                tool_denylist: acl(r.try_get("tool_denylist")?)?,
                cert_identity: r.try_get("cert_identity")?,
                registered_at: r.try_get("registered_at")?,
                expires_at: r.try_get("expires_at")?,
                revoked_at: r.try_get("revoked_at")?,
            })
        })
        .collect()
}
fn acl(raw: Option<String>) -> Result<Option<Vec<String>>, Error> {
    raw.map(|s| serde_json::from_str(&s).map_err(|_| Error::Invalid))
        .transpose()
}
async fn registrations(c: &mut SqliteConnection) -> Result<Vec<Registration>, Error> {
    let rows = sqlx::query("SELECT name, kind, upstream, egress, auth_json, disabled, created_at, updated_at FROM registrations ORDER BY name").fetch_all(c).await?;
    rows.iter()
        .map(|r| {
            Ok(Registration {
                name: r.try_get("name")?,
                kind: r.try_get("kind")?,
                upstream: r.try_get("upstream")?,
                egress: r.try_get("egress")?,
                auth: serde_json::from_str(&r.try_get::<String, _>("auth_json")?).ok(),
                disabled: r.try_get("disabled")?,
                created_at: r.try_get("created_at")?,
                updated_at: r.try_get("updated_at")?,
            })
        })
        .collect()
}
async fn bindings(c: &mut SqliteConnection) -> Result<Vec<Binding>, Error> {
    let rows = sqlx::query("SELECT agent_id, registration, auth_spec, created_at, updated_at FROM agent_credential_overrides ORDER BY agent_id, registration").fetch_all(c).await?;
    rows.iter()
        .map(|r| {
            Ok(Binding {
                agent_id: r.try_get("agent_id")?,
                registration: r.try_get("registration")?,
                auth: serde_json::from_str(&r.try_get::<String, _>("auth_spec")?).ok(),
                created_at: r.try_get("created_at")?,
                updated_at: r.try_get("updated_at")?,
            })
        })
        .collect()
}
async fn stored(c: &mut SqliteConnection) -> Result<Vec<Stored>, Error> {
    let rows = sqlx::query(
        "SELECT secret_ref, set_at, tombstoned_at FROM credential_secrets ORDER BY secret_ref",
    )
    .fetch_all(c)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(Stored {
                secret_ref: r.try_get("secret_ref")?,
                set_at: r.try_get("set_at")?,
                tombstoned_at: r.try_get("tombstoned_at")?,
            })
        })
        .collect()
}
async fn sessions(c: &mut SqliteConnection) -> Result<Vec<Session>, Error> {
    let rows = sqlx::query("SELECT name, session_label, degraded, account_id, created_at, updated_at FROM oauth_sessions ORDER BY name, session_label").fetch_all(c).await?;
    rows.iter()
        .map(|r| {
            Ok(Session {
                name: r.try_get("name")?,
                session_label: r.try_get("session_label")?,
                degraded: r.try_get("degraded")?,
                account_id: r.try_get("account_id")?,
                created_at: r.try_get("created_at")?,
                updated_at: r.try_get("updated_at")?,
            })
        })
        .collect()
}
async fn revision(c: &mut SqliteConnection) -> Result<i64, Error> {
    let value: Option<String> =
        sqlx::query_scalar("SELECT value FROM registrations_meta WHERE key=?")
            .bind(REVISION)
            .fetch_optional(c)
            .await?;
    match value {
        None => Ok(0),
        Some(v) => v.parse().ok().filter(|v| *v > 0).ok_or(Error::Conflict),
    }
}
