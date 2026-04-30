//! Per-operator authentication. C-7 (SPEC §4.2.9).
//!
//! Operator credentials live in operator-only YAML config (R-N10) so
//! the system is recoverable when the agents database is corrupted.
//! Each record:
//!
//! ```yaml
//! operators:
//!   - name: "alice"
//!     token_hash: "$argon2id$..."
//!     scope: null   # reserved (D-6)
//! ```
//!
//! T2.10's resolution: per-operator named tokens, argon2-hashed in file
//! (Q-4 / PRD §14.1 #4). Cleartext tokens live in operator password
//! managers; only hashes are at rest.
//!
//! Tokens have wire form `lk_op_<public_id>.<secret>`. The operator
//! namespace was added during T2.10 — `token::parse` validates the
//! prefix shape.

use super::AuthError;
use crate::argon2_helper;
use crate::token::{self, TokenNamespace};
use secrecy::SecretString;
use serde::Deserialize;
use std::path::Path;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct OperatorIdentity {
    pub name: String,
    /// Reserved for future fine-grained operator roles (D-6).
    pub scope: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRecord {
    pub name: String,
    pub public_id: String,
    pub token_hash: String,
    #[serde(default)]
    pub scope: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorsFile {
    pub operators: Vec<OperatorRecord>,
}

pub struct OperatorAuthenticator {
    records: RwLock<Vec<OperatorRecord>>,
    decoy_hash: String,
}

impl OperatorAuthenticator {
    /// Load operators from the configured YAML path. Failure to read or
    /// parse → fail-fast (operator credentials are R-N10's recovery
    /// principal; missing or malformed → unrecoverable state).
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            AuthError::Backend(format!("read operators file {}: {e}", path.display()))
        })?;
        let parsed: OperatorsFile = serde_yaml::from_str(&text)
            .map_err(|e| AuthError::Backend(format!("parse operators yaml: {e}")))?;
        let decoy_hash = argon2_helper::hash(&SecretString::from(
            "decoy-operator-secret-for-constant-time-on-miss".to_string(),
        ))
        .map_err(|e| AuthError::Backend(e.to_string()))?;
        Ok(Self {
            records: RwLock::new(parsed.operators),
            decoy_hash,
        })
    }

    /// Authenticate the credential carried in `Authorization: Bearer …`.
    pub async fn authenticate_bearer(&self, header: &str) -> Result<OperatorIdentity, AuthError> {
        let raw = header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::MissingCredential)?;
        let (ns, public_id, secret) = match token::parse(raw) {
            Ok(p) => p,
            Err(_) => {
                let dummy = SecretString::from("dummy".to_string());
                let _ = argon2_helper::verify(&self.decoy_hash, &dummy);
                return Err(AuthError::InvalidCredential);
            }
        };
        if !matches!(ns, TokenNamespace::Operator) {
            return Err(AuthError::InvalidCredential);
        }

        let records = self.records.read().await;
        let record = records.iter().find(|r| r.public_id == public_id.as_str());
        let Some(record) = record else {
            let dummy = SecretString::from("dummy".to_string());
            let _ = argon2_helper::verify(&self.decoy_hash, &dummy);
            return Err(AuthError::InvalidCredential);
        };

        let secret_str = SecretString::from(secret.expose().to_string());
        match argon2_helper::verify(&record.token_hash, &secret_str) {
            Ok(true) => Ok(OperatorIdentity {
                name: record.name.clone(),
                scope: record.scope.clone(),
            }),
            Ok(false) => Err(AuthError::InvalidCredential),
            Err(e) => Err(AuthError::Backend(e.to_string())),
        }
    }
}
