//! File-sealed backend (T5.1).
//!
//! Reads a credential from a path that systemd-creds (or an equivalent
//! operator process) has decrypted into a permission-restricted file —
//! typically `/run/credentials/locksmith/$NAME` when the systemd unit
//! uses `LoadCredentialEncrypted=`. For non-systemd deployments the
//! operator places plaintext at a chmod-0600 path on a tmpfs.
//!
//! Locksmith does NOT do AEAD itself. The threat boundary is "anything
//! readable by the locksmith uid is already trusted." See
//! `docs/v2/threat-model.md` for the full rationale.
//!
//! On `Drop` the cached bytes are zeroized via `zeroize::Zeroize` (the
//! `secrecy` crate guarantees this for `SecretString`).

use super::SecretRef;
use super::backend::{BackendError, SecretBackend};
use async_trait::async_trait;
use secrecy::SecretString;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::info;

pub struct FileSealedBackend {
    /// Per-path cache. Resolution is idempotent across calls so the
    /// daemon's startup-resolution + hot-reload paths share the same
    /// disk read.
    cache: Mutex<HashMap<PathBuf, SecretString>>,
    /// When false, world/group-readable files are accepted. Tests
    /// flip this off; production code path leaves it true.
    enforce_permissions: bool,
}

impl FileSealedBackend {
    /// Production constructor: enforces 0600-style permissions.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            enforce_permissions: true,
        }
    }

    /// Test-only constructor that skips permission verification.
    /// Useful for unit tests that can't easily chmod files (some
    /// tempfile setups, CI runners) but want to exercise the read +
    /// cache contract.
    #[doc(hidden)]
    pub fn new_for_tests_unchecked() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            enforce_permissions: false,
        }
    }

    fn check_permissions(path: &PathBuf) -> Result<(), BackendError> {
        let meta = std::fs::metadata(path)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(BackendError::Other(format!(
                "{}: file mode {:#o} permits group or world read; \
                 sealed credentials must be chmod 0600 or 0400",
                path.display(),
                mode
            )));
        }
        Ok(())
    }

    fn read_path(&self, path: &PathBuf) -> Result<SecretString, BackendError> {
        if self.enforce_permissions {
            Self::check_permissions(path)?;
        }
        let bytes = std::fs::read(path)?;
        // Trim trailing newline (operators often pipe `printf` /
        // `echo` into seal). Keep all interior whitespace.
        let trimmed = if let Some(stripped) = bytes.strip_suffix(b"\n") {
            stripped
        } else {
            bytes.as_slice()
        };
        let s = String::from_utf8(trimmed.to_vec()).map_err(|e| {
            BackendError::Other(format!("{}: file is not valid UTF-8: {e}", path.display()))
        })?;
        Ok(SecretString::from(s))
    }
}

impl Default for FileSealedBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretBackend for FileSealedBackend {
    async fn resolve(&self, secret_ref: &SecretRef) -> Result<SecretString, BackendError> {
        let path = match secret_ref {
            SecretRef::FromFileSealed { path } => path.clone(),
            other => {
                return Err(BackendError::NotImplemented(match other {
                    SecretRef::LegacyString(_) | SecretRef::FromEnv { .. } => {
                        "FileSealedBackend received env variant (resolver bug)"
                    }
                    SecretRef::Inline(_) => "FileSealedBackend received Inline (resolver bug)",
                    SecretRef::FromVault { .. } => "from_vault (stub only)",
                    SecretRef::FromAwsSecretsManager { .. } => {
                        "from_aws_secrets_manager (stub only)"
                    }
                    _ => "unknown variant",
                }));
            }
        };

        // Cached fast path.
        if let Some(cached) = self
            .cache
            .lock()
            .expect("file_sealed cache mutex poisoned")
            .get(&path)
        {
            return Ok(cached.clone());
        }

        let value = self.read_path(&path)?;
        info!(path = %path.display(), "file-sealed credential resolved");
        self.cache
            .lock()
            .expect("file_sealed cache mutex poisoned")
            .insert(path, value.clone());
        Ok(value)
    }

    fn kind(&self) -> &'static str {
        "file_sealed"
    }
}
