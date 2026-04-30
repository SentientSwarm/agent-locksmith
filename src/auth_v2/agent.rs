//! Per-agent authentication. C-6 (SPEC §4.2.8).
//!
//! INF-5 / Q-13 / Q-14:
//! - Tokens are structured `lk_<public_id>.<secret>`.
//! - Lookup by `public_id` (a 128-bit non-secret URL-safe base64 value)
//!   is fast and timing-leak-free — the database keys off it.
//! - Secret verification uses argon2id (`argon2_helper::verify`) which is
//!   constant-time.
//! - **Decoy verify on miss.** If the public_id doesn't exist in the
//!   agents table, we still run an argon2 verify against a stored zero
//!   hash so the wall-clock time is similar to the hit case. This is
//!   defense-in-depth: at 2^128 entropy on the public_id, the
//!   "exists/doesn't-exist" timing channel is already unattainable, but
//!   keeping the timing characteristics indistinguishable to an
//!   attacker costs us about 5ms per failed lookup.

use super::AuthError;
use crate::argon2_helper;
use crate::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};
use crate::repo::{AgentRepository, RepoError};
use crate::token;
use async_trait::async_trait;
use secrecy::SecretString;
use serde_json::json;

/// The resolved identity of an authenticated agent.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub public_id: String,
    pub name: String,
    pub tool_allowlist: Option<Vec<String>>,
    pub tool_denylist: Option<Vec<String>>,
}

/// Resolves a credential string to an `AgentIdentity`. The trait shape is
/// chosen so that the M6 mTLS implementation drops in alongside the
/// bearer impl without refactoring callers (D-7).
#[async_trait]
pub trait AgentAuthenticator: Send + Sync {
    /// Authenticate the credential carried in `Authorization: Bearer …`.
    async fn authenticate_bearer(&self, header: &str) -> Result<AgentIdentity, AuthError>;
}

pub struct BearerAuthenticator {
    repo: AgentRepository,
    /// argon2 hash of a fixed dummy secret. Used by the decoy-verify
    /// path on public_id miss to keep timing similar.
    decoy_hash: String,
    /// Optional audit sink (T3.4 / INF-13). When set, every failed
    /// authentication emits an event_class=security row.
    audit: Option<AuditRepository>,
}

impl BearerAuthenticator {
    pub fn new(repo: AgentRepository) -> Result<Self, AuthError> {
        Self::with_audit(repo, None)
    }

    /// Construct a BearerAuthenticator that emits security audit rows
    /// on every failed authentication. The daemon runtime calls this
    /// when admin substrate is enabled.
    pub fn with_audit(
        repo: AgentRepository,
        audit: Option<AuditRepository>,
    ) -> Result<Self, AuthError> {
        // Pre-compute the decoy hash once at construction. This costs
        // ~5ms on first call but every authenticate() pays only the
        // verify, not the hash.
        let decoy_secret = SecretString::from(
            "decoy-secret-for-constant-time-on-miss-do-not-use-in-production".to_string(),
        );
        let decoy_hash =
            argon2_helper::hash(&decoy_secret).map_err(|e| AuthError::Backend(e.to_string()))?;
        Ok(Self {
            repo,
            decoy_hash,
            audit,
        })
    }

    async fn audit_failure(&self, public_id: Option<&str>, reason: &'static str) {
        let Some(repo) = &self.audit else {
            return;
        };
        let event = AuditEvent {
            ts_ms: now_ms(),
            event_class: EventClass::Security,
            event: "auth_failure".to_string(),
            agent_public_id: public_id.map(str::to_string),
            decision: Decision::Denied,
            auth_method: Some("bearer".to_string()),
            details: Some(json!({ "reason": reason })),
            ..AuditEvent::default()
        };
        if let Err(e) = repo.record(&event).await {
            tracing::warn!(error = %e, "auth audit write failed");
        }
    }

    /// Walk the agents table looking for `public_id`; if found, verify
    /// the secret. If not, run a decoy verify so the timing is similar.
    async fn resolve(
        &self,
        public_id: &str,
        secret: &SecretString,
    ) -> Result<AgentIdentity, AuthError> {
        let record = self
            .repo
            .get_active_by_public_id(public_id)
            .await
            .map_err(|e| match e {
                RepoError::Sqlx(_) => AuthError::Backend(e.to_string()),
                _ => AuthError::Backend(e.to_string()),
            })?;

        let Some(record) = record else {
            // Decoy verify: run argon2 against a stored zero-hash with
            // the presented secret so the failure path takes ~the same
            // time as the success path. We discard the result — the
            // identity didn't exist.
            let _ = argon2_helper::verify(&self.decoy_hash, secret);
            self.audit_failure(None, "unknown_public_id").await;
            return Err(AuthError::InvalidCredential);
        };

        // Expiration check (R-F3 expires_at).
        if let Some(expires_at) = record.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if expires_at < now {
                // Still verify so the secret-vs-public_id timing leak is
                // closed for expired-but-correctly-secreted tokens too.
                let _ = argon2_helper::verify(&record.secret_hash, secret);
                self.audit_failure(Some(&record.public_id), "expired").await;
                return Err(AuthError::Expired);
            }
        }

        // Constant-time secret verify.
        match argon2_helper::verify(&record.secret_hash, secret) {
            Ok(true) => {}
            Ok(false) => {
                self.audit_failure(Some(&record.public_id), "secret_mismatch")
                    .await;
                return Err(AuthError::InvalidCredential);
            }
            Err(e) => return Err(AuthError::Backend(e.to_string())),
        }

        // Best-effort `last_used_at` update. Ignoring failure — auth
        // still succeeds even if the touch can't write.
        let _ = self.repo.touch_last_used(&record.public_id).await;

        Ok(AgentIdentity {
            public_id: record.public_id,
            name: record.name,
            tool_allowlist: record.tool_allowlist,
            tool_denylist: record.tool_denylist,
        })
    }
}

#[async_trait]
impl AgentAuthenticator for BearerAuthenticator {
    async fn authenticate_bearer(&self, header: &str) -> Result<AgentIdentity, AuthError> {
        let raw = header
            .strip_prefix("Bearer ")
            .ok_or(AuthError::MissingCredential)?;
        let (ns, public_id, secret) = match token::parse(raw) {
            Ok(parts) => parts,
            Err(_) => {
                // Same decoy path so malformed-token timing matches the
                // unknown-public_id path.
                let dummy_secret = SecretString::from("dummy".to_string());
                let _ = argon2_helper::verify(&self.decoy_hash, &dummy_secret);
                self.audit_failure(None, "malformed_token").await;
                return Err(AuthError::InvalidCredential);
            }
        };
        if !matches!(ns, token::TokenNamespace::Agent) {
            self.audit_failure(Some(public_id.as_str()), "wrong_namespace")
                .await;
            return Err(AuthError::InvalidCredential);
        }
        let secret_str = SecretString::from(secret.expose().to_string());
        self.resolve(public_id.as_str(), &secret_str).await
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
