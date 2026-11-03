//! Offline, reference-only account selection upgrade. No runtime reader.
mod apply;
mod inventory;
mod legacy;
mod snapshot;
mod sources;
mod types;
use sha2::{Digest, Sha256};
use sqlx::{ConnectOptions, Connection, SqliteConnection, sqlite::SqliteConnectOptions};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
pub use types::Plan;
const REVISION: &str = "explicit_bindings/v1/revision";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "migration_conflict: reviewed plan is stale, changed, or no longer eligible; preview and review again"
    )]
    Conflict,
    #[error(
        "migration_invalid: invalid plan, ACL or legacy metadata; review the documented input format"
    )]
    Invalid,
    #[error(
        "migration_database: cannot open/read/write the existing database; check schema, permissions and stopped-daemon requirements"
    )]
    Database,
}
// Never echo SQL, trigger messages, malformed JSON, source values or owner paths.
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}
pub async fn preview(database: &Path, legacy_config: Option<&Path>) -> Result<Plan, Error> {
    let mut c = connect(database, true).await?;
    let mut tx = c.begin().await?;
    let legacy = legacy::inventory(legacy_config)?;
    let snapshot = snapshot::load(&mut tx).await?;
    let plan = inventory::plan(&snapshot, legacy)?;
    tx.rollback().await?;
    c.close().await?;
    Ok(plan)
}
pub async fn apply(
    database: &Path,
    plan: &Plan,
    legacy_config: Option<&Path>,
) -> Result<usize, Error> {
    let mut c = connect(database, false).await?;
    let mut tx = c.begin_with("BEGIN IMMEDIATE").await?;
    let legacy = legacy::inventory(legacy_config)?;
    let result = apply::run(&mut tx, plan, legacy).await;
    match result {
        Ok(n) => {
            tx.commit().await?;
            c.close().await?;
            Ok(n)
        }
        Err(e) => {
            tx.rollback().await?;
            c.close().await?;
            Err(e)
        }
    }
}
async fn connect(path: &Path, read_only: bool) -> Result<SqliteConnection, Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(read_only)
        .create_if_missing(false)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        .disable_statement_logging();
    Ok(SqliteConnection::connect_with(&options).await?)
}
fn digest(value: &impl serde::Serialize) -> Result<String, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Invalid)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
