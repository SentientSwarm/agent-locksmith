//! Controlled, owner-bound consent custody. It confers no agent authority.
mod account;
pub mod api;
pub mod config;
mod operation;
mod refresh;
pub mod server;
mod store;
mod token;
mod wire;

use crate::oauth::{SealingKey, refresh::RefreshOwner};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(pub &'static str);
pub type Result<T> = std::result::Result<T, Error>;
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self("custody_failed")
    }
}
impl From<crate::oauth::SealingKeyError> for Error {
    fn from(_: crate::oauth::SealingKeyError) -> Self {
        Self("sealing_failed")
    }
}

pub struct Runtime {
    pool: SqlitePool,
    key: SealingKey,
    config: config::Config,
    run_id: String,
    owner: RefreshOwner,
    operations: Semaphore,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub session_label: String,
    pub auth_profile_id: String,
    pub client_generation: u64,
    pub requested_scopes: Vec<String>,
    pub redirect_profile_id: String,
    pub expected_config_revision: i64,
}
impl Runtime {
    pub async fn new(
        pool: SqlitePool,
        key: SealingKey,
        config: config::Config,
        owner: RefreshOwner,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        // Validate roots before accepting a URL or spawning a listener.
        for p in &config.profiles {
            token::client(p)?;
            wire::client(p)?;
        }
        // A wrong key must not create a mixed-key consent domain. Empty custody
        // has no previous key to validate; existing sealed pairs are checked
        // without changing their rows or the independent credential store.
        tokio::time::timeout(std::time::Duration::from_secs(5), validate_key(&pool, &key))
            .await
            .map_err(|_| Error("sealing_failed"))??;
        let rt = Arc::new(Self {
            pool,
            key,
            config,
            run_id: random()?,
            owner,
            operations: Semaphore::new(16),
        });
        sqlx::query("UPDATE oauth_consent_attempts SET state='expired',reason='daemon_restarted',updated_at=?,version=version+1,state_hash=NULL,verifier_ct=NULL,verifier_nonce=NULL,quarantine_ct=NULL,quarantine_nonce=NULL WHERE state IN ('pending','exchanging')")
            .bind(now()).execute(&rt.pool).await?;
        Ok(rt)
    }
    fn profile(&self, id: &str) -> Result<&config::Profile> {
        self.config
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or(Error("invalid_profile"))
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0)
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn random() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error("random_failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn digest(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(b))
}
fn parse(b: &[u8]) -> Result<Value> {
    locksmith_mcp_transport::strict_json::parse(
        b,
        locksmith_mcp_transport::Limits {
            response_bytes: 524288,
            json_units: 32768,
            ..Default::default()
        },
    )
    .map_err(|_| Error("json_refused"))
}

#[cfg(test)]
mod tests;

async fn validate_key(pool: &SqlitePool, key: &SealingKey) -> Result<()> {
    use futures_util::TryStreamExt;
    let mut rows=sqlx::query("SELECT refresh_token_ciphertext,refresh_token_nonce,access_token_ciphertext,access_token_nonce FROM oauth_sessions").fetch(pool);
    while let Some(row) = rows.try_next().await? {
        for (ct, nonce) in [
            ("refresh_token_ciphertext", "refresh_token_nonce"),
            ("access_token_ciphertext", "access_token_nonce"),
        ] {
            let ct: Option<Vec<u8>> = row.try_get(ct)?;
            let nonce: Option<Vec<u8>> = row.try_get(nonce)?;
            match (ct, nonce) {
                (Some(ct), Some(nonce)) => {
                    key.unseal(&ct, &nonce)?;
                }
                (None, None) => {}
                _ => return Err(Error("sealing_failed")),
            }
        }
    }
    Ok(())
}
