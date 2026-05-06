//! Authentication shape for a registration (wire + DB form).
//!
//! Locked at devloop `phase-e-catalog-substrate` Design phase.
//!
//! Three variants, internally tagged on `kind`:
//!
//!   `none`   — no auth header injection. **Required to be explicit** for `kind=tool`
//!              (implicit absence is rejected at register-time, closing the "operator
//!              forgot the API key" footgun). `kind=model` rejects this variant outright
//!              (no model upstream is meaningfully authless at v2.0.0).
//!   `header` — inject `<header>: <env-var-resolved-value>`. Used for `x-api-key`,
//!              custom headers, internal middleware tokens.
//!   `bearer` — inject `Authorization: Bearer <env-var-resolved-value>`. Sugar for the
//!              common bearer-auth shape; the `Bearer ` prefix is supplied by the runtime
//!              materializer, not stored in the env var.
//!
//! At v2.0.0 the wire/DB form carries env-var **names** only. Translation to
//! [`crate::secret::SecretRef`] happens at materialize-time when the runtime
//! catalog cache is built. This keeps Serialize trivial and avoids leaking
//! resolved secret values through admin GET endpoints.
//!
//! Sealed-cred-on-disk (`from_file_sealed:`) and external backends (Vault,
//! AWS Secrets Manager) remain accessible via the deprecated pre-Phase-E
//! bootstrap-from-yaml path until v0.3 removes it. v0.2 will introduce a
//! richer admin-side AuthSpec covering sealed at-rest creds.

use crate::secret::SecretRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum AuthSpec {
    None,
    Header { header: String, env_var: String },
    Bearer { env_var: String },
}

impl AuthSpec {
    /// True iff this auth shape ever injects a header.
    pub fn injects_header(&self) -> bool {
        !matches!(self, AuthSpec::None)
    }

    /// Translate to a runtime [`SecretRef`] for the credential resolver.
    /// `None` returns `None`; both `Header` and `Bearer` produce
    /// `SecretRef::FromEnv` with the variant's `env_var`.
    ///
    /// The `Bearer ` prefix is NOT added here — the proxy-side header
    /// injection adds it. Storing the prefix in the env var would
    /// contradict the canonical "the env var holds just the token"
    /// convention.
    pub fn to_secret_ref(&self) -> Option<SecretRef> {
        match self {
            AuthSpec::None => None,
            AuthSpec::Header { env_var, .. } | AuthSpec::Bearer { env_var } => {
                Some(SecretRef::FromEnv {
                    var: env_var.clone(),
                    prefix: None,
                })
            }
        }
    }
}
