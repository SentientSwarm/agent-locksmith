use secrecy::SecretString;
use sha2::{Digest, Sha256};

/// In-memory OAuth session record. Tokens are unsealed on read,
/// resealed on write. Lifetime in memory is bounded by the caller
/// (the proxy hot path materializes only the access token, briefly).
#[derive(Clone)]
pub struct OauthSession {
    /// Non-reused committed database identity; distinct from the audit display ID.
    pub incarnation: i64,
    /// Incremented by every conditional token or degradation write.
    pub token_version: i64,
    pub name: String,
    /// Session label (Phase G). Distinguishes multiple sessions under
    /// the same registration name — e.g., `(codex, "hermes")` vs
    /// `(codex, "openclaw")`. Defaults to `"default"` for shared-
    /// credential deployments.
    pub session_label: String,
    pub refresh_token: SecretString,
    pub access_token: Option<SecretString>,
    /// Unix seconds at which the access token expires. `None` only in
    /// the brief window between bootstrap (refresh-token sealed) and
    /// the daemon's first token-endpoint exchange (refresh-task or
    /// proxy-on-demand fills `access_token` + `access_token_expires_at`).
    pub access_token_expires_at: Option<i64>,
    /// Space-delimited scopes from the bootstrap response.
    pub scope: String,
    pub degraded: bool,
    pub created_at: i64,
    pub updated_at: i64,
    /// Phase G2 — provider-side account identifier extracted from the
    /// access-token JWT at bootstrap and refresh time. For codex this
    /// is the `chatgpt_account_id` claim; the proxy hot path reads it
    /// to inject the `ChatGPT-Account-ID` header alongside the bearer
    /// token. `None` for non-JWT access tokens (any other OAuth
    /// provider that doesn't follow the OpenAI claim shape) — those
    /// requests proceed without the header, which is the correct
    /// behavior for non-codex upstreams.
    pub account_id: Option<String>,
}

impl std::fmt::Debug for OauthSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthSession")
            .field("incarnation", &self.incarnation)
            .field("token_version", &self.token_version)
            .field("name", &self.name)
            .field("session_label", &self.session_label)
            .field("refresh_token", &"<sealed>")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<sealed>"),
            )
            .field("access_token_expires_at", &self.access_token_expires_at)
            .field("scope", &self.scope)
            .field("degraded", &self.degraded)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("account_id", &self.account_id)
            .finish()
    }
}

impl OauthSession {
    /// Stable session identifier per ADR-0005 D4. SHA-256 of
    /// `name + ':' + session_label + ':' + created_at`, truncated to
    /// 16 hex chars. Used as `details.oauth_session_id` in audit rows.
    /// Phase G adds session_label to the hash so two sessions under
    /// the same registration get distinct identifiers in audit. Never
    /// derived from token material.
    pub fn audit_session_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.name.as_bytes());
        hasher.update(b":");
        hasher.update(self.session_label.as_bytes());
        hasher.update(b":");
        hasher.update(self.created_at.to_string().as_bytes());
        let digest = hasher.finalize();
        // 8 bytes → 16 hex chars. Inline encoder to avoid adding the
        // `hex` crate; sha2 gives us a fixed-size GenericArray here.
        let mut out = String::with_capacity(16);
        for b in &digest[..8] {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}
