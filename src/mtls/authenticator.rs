//! T6.5 — MtlsAuthenticator (verification gate).
//!
//! Verifies a peer's leaf cert (via `MtlsValidator`) and maps the
//! validated identity to an `AgentRecord` via
//! `AgentRepository.get_by_cert_identity`. Returns the same
//! `AgentIdentity` the bearer path returns, so listener middleware
//! can treat both transports uniformly (D-7).
//!
//! Verification gate notes:
//!  - The agent's `revoked_at IS NULL` filter lives in
//!    `AgentRepository::get_by_cert_identity`, so a revoked agent
//!    yields `AuthError::InvalidCredential` here (not a stale identity).
//!  - On any validator error we map to `AuthError::InvalidCredential`
//!    rather than leaking the specific failure mode to the wire — the
//!    audit row carries the precise reason.
//!  - The audit hook fires on every InvalidCredential return (parity
//!    with BearerAuthenticator's INF-13 path). Successful binding does
//!    NOT emit a security row — that's a normal-path event recorded by
//!    the proxy/admin layer with `auth_method=mtls` per T6.10.

use std::sync::Arc;

use crate::auth_v2::{AgentIdentity, AuthError};
use crate::repo::AgentRepository;
use crate::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};
use serde_json::json;

use super::validator::{MtlsError, MtlsIdentity, MtlsValidator};

pub struct MtlsAuthenticator {
    validator: Arc<MtlsValidator>,
    repo: AgentRepository,
    audit: Option<AuditRepository>,
}

impl MtlsAuthenticator {
    pub fn new(validator: Arc<MtlsValidator>, repo: AgentRepository) -> Self {
        Self {
            validator,
            repo,
            audit: None,
        }
    }

    pub fn with_audit(
        validator: Arc<MtlsValidator>,
        repo: AgentRepository,
        audit: Option<AuditRepository>,
    ) -> Self {
        Self {
            validator,
            repo,
            audit,
        }
    }

    /// Authenticate a peer's DER-encoded client cert. The TLS layer
    /// extracts this from the handshake; the listener glue (T6.6) then
    /// hands the bytes to this method.
    pub async fn authenticate_cert(&self, cert_der: &[u8]) -> Result<AgentIdentity, AuthError> {
        let identity = self.validator.validate(cert_der).map_err(|e| {
            self.audit_failure_blocking(&e, None);
            AuthError::InvalidCredential
        })?;

        match self.repo.get_by_cert_identity(&identity.value).await {
            Ok(Some(agent)) => Ok(AgentIdentity {
                id: agent.id,
                public_id: agent.public_id,
                name: agent.name,
                tool_allowlist: agent.tool_allowlist,
                tool_denylist: agent.tool_denylist,
            }),
            Ok(None) => {
                // Cert is valid but no agent has this cert_identity.
                // Could be a misprovisioned cert or a revoked agent
                // (revoked_at filter excludes them in the repo).
                self.audit_unknown_identity(&identity);
                Err(AuthError::InvalidCredential)
            }
            Err(e) => Err(AuthError::Backend(e.to_string())),
        }
    }

    fn audit_failure_blocking(&self, error: &MtlsError, identity: Option<&MtlsIdentity>) {
        let Some(repo) = self.audit.clone() else {
            return;
        };
        let serial = identity.map(|i| i.serial_hex.clone());
        let kind = match error {
            MtlsError::UntrustedChain => "untrusted_chain",
            MtlsError::Expired => "cert_expired",
            MtlsError::NotYetValid => "cert_not_yet_valid",
            MtlsError::MalformedCert(_) => "malformed_cert",
            MtlsError::NoIdentity => "no_identity",
            MtlsError::RevokedByCRL { .. } => "revoked_by_crl",
            MtlsError::RevokedByBlocklist { .. } => "revoked_by_blocklist",
        };
        let msg = error.to_string();
        // Audit emit happens on a tokio task because authenticate_cert
        // currently calls this from a sync error path. The cost is
        // tolerable — auth failures are rare relative to successes.
        let event = AuditEvent {
            ts_ms: now_ms(),
            event_class: EventClass::Security,
            event: "mtls_auth_failure".to_string(),
            decision: Decision::Denied,
            auth_method: Some("mtls".to_string()),
            details: Some(json!({
                "reason": kind,
                "message": msg,
                "serial_hex": serial,
            })),
            ..AuditEvent::default()
        };
        tokio::spawn(async move {
            if let Err(e) = repo.record(&event).await {
                tracing::warn!(error = %e, "mtls auth failure audit write failed");
            }
        });
    }

    fn audit_unknown_identity(&self, identity: &MtlsIdentity) {
        let Some(repo) = self.audit.clone() else {
            return;
        };
        let event = AuditEvent {
            ts_ms: now_ms(),
            event_class: EventClass::Security,
            event: "mtls_unknown_identity".to_string(),
            decision: Decision::Denied,
            auth_method: Some("mtls".to_string()),
            details: Some(json!({
                "identity": identity.value,
                "kind": identity.kind,
                "serial_hex": identity.serial_hex,
            })),
            ..AuditEvent::default()
        };
        tokio::spawn(async move {
            if let Err(e) = repo.record(&event).await {
                tracing::warn!(error = %e, "mtls unknown-identity audit write failed");
            }
        });
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
