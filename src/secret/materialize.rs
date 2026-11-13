//! #159 — one place that turns a `stored_*` handle or an `op://` reference
//! into the credential value, shared by the proxy and the broker prober so
//! the two can never disagree about whether a key is usable.

use secrecy::{ExposeSecret, SecretString};

use super::{CredentialSealingKey, OpResolver};
use crate::repo::CredentialSecretsRepository;

/// Why a credential could not be materialized. Carries no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFailure {
    /// `LOCKSMITH_CREDENTIAL_SEALING_KEY` or the sealed store is unwired.
    StoreUnconfigured,
    /// The sealed value is missing or tombstoned.
    Missing,
    /// The sealed store could not be read.
    ReadFailed,
    /// The value could not be unsealed, or is empty or not UTF-8.
    Undecodable,
    /// The `op://` reference is not in the resolver cache, or is empty.
    OpUnresolved,
}

impl KeyFailure {
    /// The audit / operational-log cause for this failure.
    pub fn cause(self) -> &'static str {
        match self {
            Self::StoreUnconfigured => "credential_store_unconfigured",
            Self::Missing => "credential_unresolved",
            Self::ReadFailed => "store_read_failed",
            Self::Undecodable => "unseal_failed",
            Self::OpUnresolved => "op_reference_unresolved",
        }
    }
}

/// Fetch and unseal a `stored_*` value. The unsealed buffer is zeroized on
/// drop; the value lives on only in the returned `SecretString`.
pub async fn stored(
    key: Option<&CredentialSealingKey>,
    secrets: Option<&CredentialSecretsRepository>,
    secret_ref: &str,
) -> Result<SecretString, KeyFailure> {
    let (Some(key), Some(secrets)) = (key, secrets) else {
        return Err(KeyFailure::StoreUnconfigured);
    };
    let sealed = match secrets.get(secret_ref).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(KeyFailure::Missing),
        Err(e) => {
            tracing::warn!(secret_ref = %secret_ref, error = %e, "stored credential read failed");
            return Err(KeyFailure::ReadFailed);
        }
    };
    let plain = key
        .unseal(&sealed.sealed_value, &sealed.nonce)
        .map_err(|e| {
            tracing::warn!(secret_ref = %secret_ref, error = %e, "stored credential unseal failed");
            KeyFailure::Undecodable
        })?;
    let plain = secrecy::zeroize::Zeroizing::new(plain);
    match std::str::from_utf8(&plain) {
        Ok(s) if !s.is_empty() => Ok(SecretString::from(s)),
        _ => {
            tracing::warn!(secret_ref = %secret_ref, "stored credential is empty or not valid UTF-8");
            Err(KeyFailure::Undecodable)
        }
    }
}

/// Read an `op://` value from the resolver cache (never shells `op`).
pub fn op(resolver: Option<&OpResolver>, reference: &str) -> Result<SecretString, KeyFailure> {
    match resolver.and_then(|r| r.get(reference)) {
        Some(v) if !v.expose_secret().is_empty() => Ok(v),
        _ => Err(KeyFailure::OpUnresolved),
    }
}
