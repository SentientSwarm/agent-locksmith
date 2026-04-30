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
use crate::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};
use crate::token::{self, TokenNamespace};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
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
    /// Cert identity for mTLS-authenticated operators (M6 / T6.7 / D-9).
    /// When set, an operator can authenticate by presenting a client
    /// cert whose extracted identity matches this value. The bearer
    /// path remains available; both shapes resolve to the same
    /// `OperatorIdentity`.
    #[serde(default)]
    pub cert_identity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorsFile {
    pub operators: Vec<OperatorRecord>,
}

pub struct OperatorAuthenticator {
    records: RwLock<Vec<OperatorRecord>>,
    decoy_hash: String,
    audit: Option<AuditRepository>,
}

impl OperatorAuthenticator {
    /// Load operators from the configured YAML path. Failure to read or
    /// parse → fail-fast (operator credentials are R-N10's recovery
    /// principal; missing or malformed → unrecoverable state).
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        Self::load_with_audit(path, None)
    }

    /// Load operators and attach an audit sink that captures every
    /// failed authentication as event_class=security (T3.4 / INF-13).
    pub fn load_with_audit(path: &Path, audit: Option<AuditRepository>) -> Result<Self, AuthError> {
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
            audit,
        })
    }

    async fn audit_failure(&self, operator_name: Option<&str>, reason: &'static str) {
        let Some(repo) = &self.audit else {
            return;
        };
        let event = AuditEvent {
            ts_ms: now_ms(),
            event_class: EventClass::Security,
            event: "operator_auth_failure".to_string(),
            operator_name: operator_name.map(str::to_string),
            decision: Decision::Denied,
            auth_method: Some("bearer".to_string()),
            details: Some(json!({ "reason": reason })),
            ..AuditEvent::default()
        };
        if let Err(e) = repo.record(&event).await {
            tracing::warn!(error = %e, "operator auth audit write failed");
        }
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
                self.audit_failure(None, "malformed_token").await;
                return Err(AuthError::InvalidCredential);
            }
        };
        if !matches!(ns, TokenNamespace::Operator) {
            self.audit_failure(None, "wrong_namespace").await;
            return Err(AuthError::InvalidCredential);
        }

        let records = self.records.read().await;
        let record = records.iter().find(|r| r.public_id == public_id.as_str());
        let Some(record) = record else {
            let dummy = SecretString::from("dummy".to_string());
            let _ = argon2_helper::verify(&self.decoy_hash, &dummy);
            drop(records);
            self.audit_failure(None, "unknown_public_id").await;
            return Err(AuthError::InvalidCredential);
        };

        let secret_str = SecretString::from(secret.expose().to_string());
        match argon2_helper::verify(&record.token_hash, &secret_str) {
            Ok(true) => Ok(OperatorIdentity {
                name: record.name.clone(),
                scope: record.scope.clone(),
            }),
            Ok(false) => {
                let name = record.name.clone();
                drop(records);
                self.audit_failure(Some(&name), "secret_mismatch").await;
                Err(AuthError::InvalidCredential)
            }
            Err(e) => Err(AuthError::Backend(e.to_string())),
        }
    }

    /// Authenticate by an mTLS-extracted cert identity (T6.7 / D-9).
    /// Returns the matching `OperatorIdentity` or `InvalidCredential`
    /// when no operator declares this identity. The cert chain itself
    /// must already be validated by `MtlsValidator` before this call —
    /// we trust the identity string the caller passes.
    ///
    /// Audit: a miss emits `operator_auth_failure` with reason
    /// `unknown_cert_identity` and `auth_method=mtls`.
    pub async fn authenticate_cert_identity(
        &self,
        cert_identity: &str,
    ) -> Result<OperatorIdentity, AuthError> {
        let records = self.records.read().await;
        let hit = records
            .iter()
            .find(|r| r.cert_identity.as_deref() == Some(cert_identity));
        if let Some(record) = hit {
            return Ok(OperatorIdentity {
                name: record.name.clone(),
                scope: record.scope.clone(),
            });
        }
        drop(records);
        self.audit_cert_identity_failure(cert_identity).await;
        Err(AuthError::InvalidCredential)
    }

    async fn audit_cert_identity_failure(&self, cert_identity: &str) {
        let Some(repo) = &self.audit else {
            return;
        };
        let event = AuditEvent {
            ts_ms: now_ms(),
            event_class: EventClass::Security,
            event: "operator_auth_failure".to_string(),
            decision: Decision::Denied,
            auth_method: Some("mtls".to_string()),
            details: Some(json!({
                "reason": "unknown_cert_identity",
                "cert_identity": cert_identity,
            })),
            ..AuditEvent::default()
        };
        if let Err(e) = repo.record(&event).await {
            tracing::warn!(error = %e, "operator cert-identity audit write failed");
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
