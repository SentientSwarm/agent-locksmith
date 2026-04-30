//! Secret backend trait + dispatching resolver (T2.19, C-14).

use super::SecretRef;
use async_trait::async_trait;
use secrecy::SecretString;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// A required environment variable or file is missing. Carries the
    /// missing identifier (var name or path) for operator-visible
    /// diagnostics — never any secret material.
    #[error("missing: {0}")]
    Missing(String),
    /// The backend implementation does not support this `SecretRef`
    /// variant. Vault and AWS land as stubs in v0.6.0 — both return
    /// this error from `resolve()`.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    /// Filesystem / IO error. Used by `FileSealedBackend` for
    /// permission and read failures.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Backend-specific error message. Generic catch-all so impls can
    /// surface their own diagnostics without a per-backend variant.
    #[error("{0}")]
    Other(String),
}

/// A pluggable secret-resolution backend.
///
/// `resolve` consumes a `SecretRef` and returns the resolved bytes as a
/// `SecretString`. Implementations should:
/// - Be safe to call concurrently (`Send + Sync`).
/// - Cache resolved values when the upstream is expensive (file IO,
///   network); the daemon resolves at startup so the steady-state
///   request path doesn't re-resolve.
/// - Zeroize their own internal state on `Drop` if they hold any
///   long-lived resolved bytes.
#[async_trait]
pub trait SecretBackend: Send + Sync {
    async fn resolve(&self, secret_ref: &SecretRef) -> Result<SecretString, BackendError>;

    /// Diagnostic name. Logged at resolve time; never includes secret
    /// material.
    fn kind(&self) -> &'static str;
}

/// Composite resolver: dispatches each `SecretRef` variant to its
/// matching backend. The daemon constructs one `SecretResolver` at
/// startup and walks every `tool.auth.value` through it.
pub struct SecretResolver {
    env: super::EnvBackend,
    file_sealed: Option<super::FileSealedBackend>,
}

impl SecretResolver {
    /// Resolver wired with only the env backend. Vault / AWS / sealed
    /// variants → `NotImplemented`. Suitable for M0/M1 backward-compat.
    pub fn env_only() -> Self {
        Self {
            env: super::EnvBackend::new(),
            file_sealed: None,
        }
    }

    /// Resolver wired with env + file-sealed backends. M5 production
    /// shape; Vault / AWS still `NotImplemented` per T5.3.
    pub fn with_file_sealed(file_sealed: super::FileSealedBackend) -> Self {
        Self {
            env: super::EnvBackend::new(),
            file_sealed: Some(file_sealed),
        }
    }

    pub async fn resolve(&self, sr: &SecretRef) -> Result<SecretString, BackendError> {
        match sr {
            SecretRef::Inline(s) => Ok(s.clone()),
            SecretRef::LegacyString(_) | SecretRef::FromEnv { .. } => self.env.resolve(sr).await,
            SecretRef::FromFileSealed { .. } => match &self.file_sealed {
                Some(b) => b.resolve(sr).await,
                None => Err(BackendError::NotImplemented(
                    "from_file_sealed (no FileSealedBackend configured)",
                )),
            },
            SecretRef::FromVault { .. } => {
                Err(BackendError::NotImplemented("from_vault (M6+ — stub only)"))
            }
            SecretRef::FromAwsSecretsManager { .. } => Err(BackendError::NotImplemented(
                "from_aws_secrets_manager (M6+ — stub only)",
            )),
        }
    }
}
