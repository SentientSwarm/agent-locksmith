//! Authentication shape for a registration (wire + DB form).
//!
//! Locked at devloop `phase-e-catalog-substrate` Design phase. Extended at
//! Phase F (OAuth — see ADR-0005).
//!
//! Seven variants, internally tagged on `kind`:
//!
//!   `stored_header` / `stored_bearer` — Phase J `stored` custody backend
//!                         (ADR-0008). Same wire injection as `header`/`bearer`
//!                         but the value is sealed at rest in `credential_secrets`;
//!                         the variant carries only an opaque `secret_ref` handle,
//!                         never a value. Unsealed at inject-time (T1.6).
//!
//!   `none`              — no auth header injection. Required to be explicit for
//!                         `kind=tool` (implicit absence is rejected at register-time,
//!                         closing the "operator forgot the API key" footgun).
//!                         `kind=model` accepts `none` for LAN-local self-hosted
//!                         inference (Ollama, LM Studio) but rejects implicit absence.
//!   `header`            — inject `<header>: <env-var-resolved-value>`. Used for
//!                         `x-api-key`, custom headers, internal middleware tokens.
//!   `bearer`            — inject `Authorization: Bearer <env-var-resolved-value>`.
//!                         The `Bearer ` prefix is supplied by the runtime materializer,
//!                         not stored in the env var.
//!   `oauth_pkce`        — OAuth 2.0 with PKCE (Proof Key for Code Exchange). First-time
//!                         auth via browser redirect; subsequent calls use the cached
//!                         access token (refreshed transparently by the daemon). See
//!                         ADR-0005 D1.
//!   `oauth_device_code` — OAuth 2.0 with device-code flow. First-time auth prints a
//!                         user_code + verification URL, polls the token endpoint for
//!                         completion. Used by codex / copilot / qwen-cli. See ADR-0005 D1.
//!
//! Static-credential variants (`none` / `header` / `bearer`) carry env-var **names**
//! only; translation to [`crate::secret::SecretRef`] happens at materialize-time.
//! OAuth variants carry public client metadata only — no secrets in the wire/DB
//! form. The actual refresh + access tokens live in the `oauth_sessions` table
//! sealed via AES-GCM (ADR-0005 D2).
//!
//! Sealed-cred-on-disk (`from_file_sealed:`) and external backends (Vault,
//! AWS Secrets Manager) remain accessible via the deprecated pre-Phase-E
//! bootstrap-from-yaml path until v0.3 removes it.

use crate::secret::SecretRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthSpec {
    None,
    Header {
        header: String,
        env_var: String,
    },
    Bearer {
        env_var: String,
    },
    /// Phase J (ADR-0008): `stored` custody backend — inject
    /// `<header>: <unsealed-value>`. Carries only the opaque
    /// `secret_ref` handle into the `credential_secrets` sealed store;
    /// the value is sealed at rest with the credential sealing key and
    /// unsealed at inject-time (T1.6). **Never carries a value.**
    StoredHeader {
        header: String,
        secret_ref: String,
    },
    /// Phase J (ADR-0008): `stored` custody backend — inject
    /// `Authorization: Bearer <unsealed-value>`. Carries only the
    /// `secret_ref` handle (see [`AuthSpec::StoredHeader`]).
    StoredBearer {
        secret_ref: String,
    },
    /// Phase J / M2 (CCS-2): `op` custody backend — inject
    /// `<header>: <op-resolved-value>`. Carries only an
    /// `op://vault/item/field` **reference**, never a value. The value is
    /// resolved out-of-band by [`crate::secret::OpResolver`] at startup +
    /// on catalog change (never per request) and injected from the
    /// resolver's cache on the hot path (T2.3). **Never carries a value.**
    OpHeader {
        header: String,
        reference: String,
    },
    /// Phase J / M2 (CCS-2): `op` custody backend — inject
    /// `Authorization: Bearer <op-resolved-value>`. Carries only the
    /// `op://` reference (see [`AuthSpec::OpHeader`]).
    OpBearer {
        reference: String,
    },
    /// OAuth 2.0 PKCE flow (RFC 7636). Used by anthropic-oauth,
    /// google-gemini-cli. First-time auth opens a browser to `auth_url`
    /// with a code-challenge; the operator-host loopback receives the
    /// auth code; daemon exchanges it at `token_url` and seals the
    /// refresh token in `oauth_sessions`.
    OauthPkce {
        client_id: String,
        /// Loopback URI the daemon's bootstrap CLI listens on.
        /// Conventionally `http://127.0.0.1:<port>/callback` with port
        /// chosen at bootstrap time.
        redirect_uri: String,
        scopes: Vec<String>,
        auth_url: String,
        token_url: String,
        /// Phase G: optional OAuth session label. Meaningful only on
        /// `agent_credential_overrides` rows — points the proxy hot
        /// path at a specific session under the registration's name.
        /// `None` (the default) means "use the
        /// [`crate::oauth::session::DEFAULT_SESSION_LABEL`] session"
        /// — the only label that exists on default-shaped catalogs.
        /// Always `None` on registration rows themselves; only set
        /// when an override redirects an agent to a non-default
        /// session.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_label: Option<String>,
    },
    /// OAuth 2.0 device-code flow (RFC 8628). Used by codex (ChatGPT
    /// Plus), GitHub Copilot, qwen-cli. First-time auth prints a
    /// user_code + verification URL; daemon polls `token_url` until the
    /// user completes the auth in a browser elsewhere.
    OauthDeviceCode {
        client_id: String,
        scopes: Vec<String>,
        device_url: String,
        token_url: String,
        /// Phase G: see [`AuthSpec::OauthPkce::session_label`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_label: Option<String>,
    },
}

impl AuthSpec {
    /// True iff this auth shape ever injects a header on a proxied
    /// request. OAuth variants return `true` because the daemon
    /// injects `Authorization: Bearer <access_token>` after refreshing
    /// the token cache.
    pub fn injects_header(&self) -> bool {
        !matches!(self, AuthSpec::None)
    }

    /// True iff this auth shape uses the OAuth flow (either PKCE or
    /// device-code). The proxy hot path treats OAuth distinctly from
    /// static-credential variants: it reads access tokens from the
    /// `oauth_sessions` cache rather than the static `resolved_creds`
    /// map, and triggers refresh-on-401-then-retry.
    pub fn is_oauth(&self) -> bool {
        matches!(
            self,
            AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. }
        )
    }

    /// Phase G: the OAuth session label this AuthSpec resolves to.
    /// `None` for non-OAuth variants. For OAuth variants, returns the
    /// custom label if one was set on the spec, else `None` to signal
    /// "fall back to [`crate::oauth::session::DEFAULT_SESSION_LABEL`]".
    /// Callers should resolve via `.session_label_or_default()`.
    pub fn oauth_session_label(&self) -> Option<&str> {
        match self {
            AuthSpec::OauthPkce { session_label, .. }
            | AuthSpec::OauthDeviceCode { session_label, .. } => session_label.as_deref(),
            _ => None,
        }
    }

    /// OAuth session label to actually use at hot-path resolution
    /// time, with `DEFAULT_SESSION_LABEL` as the fallback. Returns
    /// `None` for non-OAuth variants.
    pub fn session_label_or_default(&self) -> Option<&str> {
        if !self.is_oauth() {
            return None;
        }
        Some(
            self.oauth_session_label()
                .unwrap_or(crate::oauth::session::DEFAULT_SESSION_LABEL),
        )
    }

    /// Translate to a runtime [`SecretRef`] for the static-credential
    /// resolver. `None` and OAuth variants return `None` (they do not
    /// resolve via env-var indirection); `Header` / `Bearer` produce
    /// `SecretRef::FromEnv` with the variant's `env_var`.
    ///
    /// The `Bearer ` prefix is NOT added here — the proxy-side header
    /// injection adds it. Storing the prefix in the env var would
    /// contradict the canonical "the env var holds just the token"
    /// convention.
    pub fn to_secret_ref(&self) -> Option<SecretRef> {
        match self {
            // `stored_*` resolve via the sealed `credential_secrets`
            // store at inject-time (T1.6), not the env-var static
            // resolver, so they yield no env-backed SecretRef here.
            AuthSpec::None
            | AuthSpec::StoredHeader { .. }
            | AuthSpec::StoredBearer { .. }
            // `op_*` resolve via the OpResolver cache (T2.3), not the
            // env-var static resolver, so they yield no env-backed
            // SecretRef here.
            | AuthSpec::OpHeader { .. }
            | AuthSpec::OpBearer { .. }
            | AuthSpec::OauthPkce { .. }
            | AuthSpec::OauthDeviceCode { .. } => None,
            AuthSpec::Header { env_var, .. } | AuthSpec::Bearer { env_var } => {
                Some(SecretRef::FromEnv {
                    var: env_var.clone(),
                    prefix: None,
                })
            }
        }
    }

    /// True iff this is a `stored` custody variant (Phase J, ADR-0008):
    /// the credential value is sealed in `credential_secrets` and
    /// unsealed at inject-time rather than resolved from an env var.
    pub fn is_stored(&self) -> bool {
        matches!(
            self,
            AuthSpec::StoredHeader { .. } | AuthSpec::StoredBearer { .. }
        )
    }

    /// The `credential_secrets` handle for a `stored` variant, else
    /// `None`. Used by the set-value path (to tombstone the prior
    /// secret on rotation) and the proxy hot path (to fetch + unseal
    /// the value for injection).
    pub fn stored_secret_ref(&self) -> Option<&str> {
        match self {
            AuthSpec::StoredHeader { secret_ref, .. } | AuthSpec::StoredBearer { secret_ref } => {
                Some(secret_ref.as_str())
            }
            _ => None,
        }
    }

    /// True iff this is an `op` custody variant (Phase J / M2, CCS-2): the
    /// credential value is resolved from an `op://` reference by the
    /// [`crate::secret::OpResolver`] cache at inject-time rather than
    /// sealed at rest or read from an env var.
    pub fn is_op(&self) -> bool {
        matches!(self, AuthSpec::OpHeader { .. } | AuthSpec::OpBearer { .. })
    }

    /// The `op://vault/item/field` reference for an `op` variant, else
    /// `None`. Used by the OpResolver to build its resolution set and by
    /// the proxy hot path to look up the cached value for injection.
    pub fn op_reference(&self) -> Option<&str> {
        match self {
            AuthSpec::OpHeader { reference, .. } | AuthSpec::OpBearer { reference } => {
                Some(reference.as_str())
            }
            _ => None,
        }
    }

    /// Validate an `op` variant's reference carries the `op://` scheme.
    /// Non-`op` variants pass trivially. The register-time validator
    /// calls this so a malformed reference is rejected before it reaches
    /// the resolver (which would otherwise silently degrade it).
    pub fn validate_op_reference(&self) -> Result<(), String> {
        match self {
            AuthSpec::OpHeader { reference, .. } | AuthSpec::OpBearer { reference } => {
                if reference.starts_with("op://") && reference.len() > "op://".len() {
                    Ok(())
                } else {
                    Err(format!(
                        "op custody reference must use the op:// scheme, got: {reference}"
                    ))
                }
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_bearer_serde_roundtrip_and_tag() {
        let spec = AuthSpec::StoredBearer {
            secret_ref: "cs_deadbeef".to_string(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains(r#""kind":"stored_bearer""#), "tag: {json}");
        assert!(json.contains(r#""secret_ref":"cs_deadbeef""#));
        // No value ever appears in the serialized shape.
        assert!(!json.to_lowercase().contains("value"));
        let back: AuthSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn stored_header_serde_roundtrip_and_tag() {
        let spec = AuthSpec::StoredHeader {
            header: "x-api-key".to_string(),
            secret_ref: "cs_abc123".to_string(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains(r#""kind":"stored_header""#), "tag: {json}");
        let back: AuthSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn is_stored_and_secret_ref_accessor() {
        let sh = AuthSpec::StoredHeader {
            header: "x".into(),
            secret_ref: "cs_1".into(),
        };
        let sb = AuthSpec::StoredBearer {
            secret_ref: "cs_2".into(),
        };
        assert!(sh.is_stored());
        assert!(sb.is_stored());
        assert_eq!(sh.stored_secret_ref(), Some("cs_1"));
        assert_eq!(sb.stored_secret_ref(), Some("cs_2"));

        let env = AuthSpec::Bearer {
            env_var: "TOK".into(),
        };
        assert!(!env.is_stored());
        assert_eq!(env.stored_secret_ref(), None);
        assert!(!AuthSpec::None.is_stored());
    }

    #[test]
    fn op_bearer_serde_roundtrip_and_tag() {
        let spec = AuthSpec::OpBearer {
            reference: "op://vault/item/field".to_string(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains(r#""kind":"op_bearer""#), "tag: {json}");
        assert!(json.contains(r#""reference":"op://vault/item/field""#));
        // No value ever appears in the serialized shape.
        assert!(!json.to_lowercase().contains("value"));
        let back: AuthSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn op_header_serde_roundtrip_and_tag() {
        let spec = AuthSpec::OpHeader {
            header: "x-api-key".to_string(),
            reference: "op://vault/item/field".to_string(),
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains(r#""kind":"op_header""#), "tag: {json}");
        let back: AuthSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn is_op_and_reference_accessor() {
        let oh = AuthSpec::OpHeader {
            header: "x".into(),
            reference: "op://v/i/f".into(),
        };
        let ob = AuthSpec::OpBearer {
            reference: "op://v/i/g".into(),
        };
        assert!(oh.is_op());
        assert!(ob.is_op());
        assert_eq!(oh.op_reference(), Some("op://v/i/f"));
        assert_eq!(ob.op_reference(), Some("op://v/i/g"));
        // op variants inject a header but are neither stored nor oauth,
        // and never resolve via the env-var static resolver.
        assert!(ob.injects_header());
        assert!(!ob.is_stored());
        assert!(!ob.is_oauth());
        assert!(ob.to_secret_ref().is_none());

        let env = AuthSpec::Bearer {
            env_var: "TOK".into(),
        };
        assert!(!env.is_op());
        assert_eq!(env.op_reference(), None);
    }

    #[test]
    fn validate_op_reference_rejects_non_op_scheme() {
        assert!(
            AuthSpec::OpBearer {
                reference: "op://vault/item/field".into(),
            }
            .validate_op_reference()
            .is_ok()
        );
        assert!(
            AuthSpec::OpBearer {
                reference: "https://not-op".into(),
            }
            .validate_op_reference()
            .is_err()
        );
        assert!(
            AuthSpec::OpBearer {
                reference: "op://".into(),
            }
            .validate_op_reference()
            .is_err(),
            "bare scheme with no path is rejected"
        );
        // Non-op variants pass trivially.
        assert!(AuthSpec::None.validate_op_reference().is_ok());
    }

    #[test]
    fn stored_variants_inject_but_are_not_oauth_and_have_no_env_secret_ref() {
        let sb = AuthSpec::StoredBearer {
            secret_ref: "cs_x".into(),
        };
        assert!(sb.injects_header(), "stored injects a header");
        assert!(!sb.is_oauth());
        // Does not resolve via the env-var static resolver.
        assert!(sb.to_secret_ref().is_none());
        assert_eq!(sb.session_label_or_default(), None);
    }

    /// CCS-4 reveal-never guard: no AuthSpec variant may carry a credential
    /// *value* in its serialized (read / DB / wire) form. AuthSpec holds
    /// only names / handles / public metadata — the stored value lives
    /// sealed in `credential_secrets`, keyed by `secret_ref`. This test
    /// enumerates every variant and asserts each serialized object's keys
    /// are drawn only from a fixed allowlist of non-secret fields, so if
    /// anyone ever adds a value-bearing field to AuthSpec it fails loudly.
    #[test]
    fn no_authspec_variant_serializes_a_value() {
        // Field names that are allowed to appear — none of them holds a
        // secret value (they are names, handles, urls, or public client
        // metadata).
        let allowed: std::collections::HashSet<&str> = [
            "kind",
            "header",
            "env_var",
            "secret_ref",
            "reference",
            "client_id",
            "redirect_uri",
            "scopes",
            "auth_url",
            "token_url",
            "device_url",
            "session_label",
        ]
        .into_iter()
        .collect();

        // A sentinel we plant in every *name/ref/metadata* field; it must
        // never be interpretable as a value key. (It appears as a value of
        // an allowed key, which is fine — those keys are names, not secrets.)
        let every_variant = vec![
            AuthSpec::None,
            AuthSpec::Header {
                header: "x-api-key".into(),
                env_var: "TOOL_KEY".into(),
            },
            AuthSpec::Bearer {
                env_var: "TOOL_KEY".into(),
            },
            AuthSpec::StoredHeader {
                header: "x-api-key".into(),
                secret_ref: "cs_ref".into(),
            },
            AuthSpec::StoredBearer {
                secret_ref: "cs_ref".into(),
            },
            AuthSpec::OpHeader {
                header: "x-api-key".into(),
                reference: "op://vault/item/field".into(),
            },
            AuthSpec::OpBearer {
                reference: "op://vault/item/field".into(),
            },
            AuthSpec::OauthPkce {
                client_id: "cid".into(),
                redirect_uri: "http://127.0.0.1/cb".into(),
                scopes: vec!["s".into()],
                auth_url: "https://a".into(),
                token_url: "https://t".into(),
                session_label: Some("lbl".into()),
            },
            AuthSpec::OauthDeviceCode {
                client_id: "cid".into(),
                scopes: vec!["s".into()],
                device_url: "https://d".into(),
                token_url: "https://t".into(),
                session_label: None,
            },
        ];

        for spec in every_variant {
            let val = serde_json::to_value(&spec).unwrap();
            let obj = val.as_object().expect("AuthSpec serializes to an object");
            for key in obj.keys() {
                assert!(
                    allowed.contains(key.as_str()),
                    "AuthSpec {spec:?} serialized an unexpected field `{key}` — \
                     a value-bearing field would break the reveal-never invariant",
                );
            }
        }
    }
}
