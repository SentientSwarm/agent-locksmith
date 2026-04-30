//! Env-var backend (T2.19): resolves `LegacyString` and `FromEnv`
//! variants. `LegacyString` walks `${VAR}` patterns textually — the M0
//! pre-parse path lifted into a typed location so the deprecation
//! warning fires once per field via the existing INF-24 registry.

use super::SecretRef;
use super::backend::{BackendError, SecretBackend};
use async_trait::async_trait;
use secrecy::SecretString;
use std::sync::Once;
use tracing::warn;

pub struct EnvBackend {
    /// One-shot warning per process for the legacy expansion path.
    /// Keeps log noise bounded even when many tools use the legacy
    /// form (INF-24).
    warned_legacy: Once,
}

impl Default for EnvBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvBackend {
    pub fn new() -> Self {
        Self {
            warned_legacy: Once::new(),
        }
    }

    /// Sync sibling of `resolve` for `LegacyString` + `FromEnv`. Used
    /// by `secret::resolve_tool_creds_sync_env_only` for the
    /// non-daemon AppState construction path.
    pub fn resolve_sync(&self, secret_ref: &SecretRef) -> Result<SecretString, BackendError> {
        match secret_ref {
            SecretRef::LegacyString(raw) => {
                self.warned_legacy.call_once(|| {
                    warn!(
                        "tool.auth.value uses legacy plain-string form with ${{VAR}} expansion; \
                         migrate to typed `from_env: {{ var: ... }}` per INF-24"
                    );
                });
                Ok(SecretString::from(Self::expand_legacy(raw)))
            }
            SecretRef::FromEnv { var, prefix } => {
                let value = std::env::var(var).map_err(|_| BackendError::Missing(var.clone()))?;
                let merged = match prefix {
                    Some(p) => format!("{p}{value}"),
                    None => value,
                };
                Ok(SecretString::from(merged))
            }
            _ => Err(BackendError::NotImplemented(
                "EnvBackend::resolve_sync only handles LegacyString and FromEnv",
            )),
        }
    }

    /// Walk `${VAR}` patterns over `input`; missing vars expand to
    /// empty string (matches the M0 textual expander's behavior so
    /// existing configs don't regress).
    fn expand_legacy(input: &str) -> String {
        let mut result = input.to_string();
        while let Some(start) = result.find("${") {
            if let Some(end) = result[start..].find('}') {
                let var_name = &result[start + 2..start + end];
                let value = std::env::var(var_name).unwrap_or_default();
                result = format!(
                    "{}{}{}",
                    &result[..start],
                    value,
                    &result[start + end + 1..]
                );
            } else {
                break;
            }
        }
        result
    }
}

#[async_trait]
impl SecretBackend for EnvBackend {
    async fn resolve(&self, secret_ref: &SecretRef) -> Result<SecretString, BackendError> {
        match secret_ref {
            SecretRef::LegacyString(raw) => {
                self.warned_legacy.call_once(|| {
                    warn!(
                        "tool.auth.value uses legacy plain-string form with ${{VAR}} expansion; \
                         migrate to typed `from_env: {{ var: ... }}` per INF-24"
                    );
                });
                Ok(SecretString::from(Self::expand_legacy(raw)))
            }
            SecretRef::FromEnv { var, prefix } => {
                let value = std::env::var(var).map_err(|_| BackendError::Missing(var.clone()))?;
                let merged = match prefix {
                    Some(p) => format!("{p}{value}"),
                    None => value,
                };
                Ok(SecretString::from(merged))
            }
            other => Err(BackendError::NotImplemented(match other {
                SecretRef::Inline(_) => "EnvBackend received Inline (resolver bug)",
                SecretRef::FromFileSealed { .. } => "from_file_sealed (use FileSealedBackend)",
                SecretRef::FromVault { .. } => "from_vault (stub only)",
                SecretRef::FromAwsSecretsManager { .. } => "from_aws_secrets_manager (stub only)",
                _ => "unknown variant",
            })),
        }
    }

    fn kind(&self) -> &'static str {
        "env"
    }
}
