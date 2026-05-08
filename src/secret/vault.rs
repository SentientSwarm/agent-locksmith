//! HashiCorp Vault backend (T5.3 — stub only in v0.6.0).
//!
//! Lands in v2 as a documented contract so consumers and downstream
//! integrators know what an implementation must do. `resolve()` returns
//! `BackendError::NotImplemented` for now; this backend is **not**
//! registered in the active `SecretResolver` dispatch (see
//! `secret::backend::SecretResolver`).
//!
//! Implementer's contract (for whoever lands the live impl, post-v2):
//!
//! 1. Authentication: AppRole or Kubernetes ServiceAccount, configured
//!    out-of-band. The constructor takes the auth identity; the live
//!    impl is responsible for token refresh.
//! 2. TTL caching: on `resolve(SecretRef::FromVault { mount, path,
//!    field })`, look up `mount/path` in the cache. If the cached
//!    value's lease is still valid (TTL > 0 with safety margin),
//!    return it. Otherwise hit Vault, persist `(value, lease_expiry)`
//!    in the cache, and return the value.
//! 3. Failure mode: Vault unreachable → return cached value if still
//!    valid; otherwise `BackendError::Other`. **Never panic.** Per
//!    Q-12, Vault outages must not take Locksmith down for tools that
//!    have already resolved.
//! 4. Lease renewal: a background task renews leases approaching
//!    expiry. The `Drop` impl revokes the leases the daemon owns.
//!
//! Until that lands, operators relying on Vault should use M0's env
//! injection path with a Vault-Agent-templated env file.

use super::SecretRef;
use super::backend::{BackendError, SecretBackend};
use async_trait::async_trait;
use secrecy::SecretString;

/// Stub. Constructible to keep call sites typeable, but `resolve()`
/// errors with `NotImplemented`. Live impl tracked outside v2.
#[derive(Debug, Default)]
pub struct VaultBackend {
    _addr: Option<String>,
}

impl VaultBackend {
    /// Stub constructor. Live impl will take auth config + TTL params.
    pub fn new(addr: Option<String>) -> Self {
        Self { _addr: addr }
    }
}

#[async_trait]
impl SecretBackend for VaultBackend {
    async fn resolve(&self, _secret_ref: &SecretRef) -> Result<SecretString, BackendError> {
        Err(BackendError::NotImplemented(
            "VaultBackend is a v2 stub; live impl tracked post-v2",
        ))
    }

    fn kind(&self) -> &'static str {
        "vault"
    }
}
