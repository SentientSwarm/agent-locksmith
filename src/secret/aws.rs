//! AWS Secrets Manager backend (T5.3 — stub only in v0.6.0).
//!
//! Lands in v2 as a documented contract; `resolve()` returns
//! `NotImplemented`. Not registered in the active dispatch.
//!
//! Implementer's contract (for whoever lands the live impl, post-v2):
//!
//! 1. Authentication: standard AWS SDK credential chain (env, profile,
//!    instance profile, IRSA). No additional config beyond region.
//! 2. TTL caching: on `resolve(SecretRef::FromAwsSecretsManager {
//!    secret_id, version_stage, field })`, cache by `(secret_id,
//!    version_stage)` with a TTL bound (default 5 minutes, override
//!    via constructor) to bound API call rate.
//! 3. Field extraction: when `field` is set, parse the cached value
//!    as JSON and pluck `[field]`. Cache the parsed value too — don't
//!    re-parse on every resolve.
//! 4. Failure mode: AWS API error → return cached value if still
//!    within TTL; otherwise `BackendError::Other`. Match Vault's
//!    "stale-but-up beats fresh-and-down" posture (Q-12).
//!
//! Until that lands, operators on AWS should use M0's env injection
//! path with the secret materialized via SSM ParameterStore + an env
//! file.

use super::SecretRef;
use super::backend::{BackendError, SecretBackend};
use async_trait::async_trait;
use secrecy::SecretString;

#[derive(Debug, Default)]
pub struct AwsSecretsManagerBackend {
    _region: Option<String>,
}

impl AwsSecretsManagerBackend {
    /// Stub constructor. Live impl will take a TTL + an optional
    /// custom client builder.
    pub fn new(region: Option<String>) -> Self {
        Self { _region: region }
    }
}

#[async_trait]
impl SecretBackend for AwsSecretsManagerBackend {
    async fn resolve(&self, _secret_ref: &SecretRef) -> Result<SecretString, BackendError> {
        Err(BackendError::NotImplemented(
            "AwsSecretsManagerBackend is a v2 stub; live impl tracked post-v2",
        ))
    }

    fn kind(&self) -> &'static str {
        "aws_secrets_manager"
    }
}
