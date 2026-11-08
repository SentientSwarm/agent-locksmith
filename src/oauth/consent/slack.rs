//! Fixed confidential profile; fixture endpoints never substitute into the real kind.
use super::{
    Error, Result,
    config::{Profile, endpoint, https},
    identifier,
};

pub(super) const SCOPES: [&str; 2] = ["search:read.public", "channels:history"];

impl Profile {
    pub(crate) fn slack(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "slack-confidential-v1" | "slack-confidential-fixture-v1"
        )
    }
    pub(crate) fn scopes(&self) -> Vec<String> {
        if self.slack() {
            SCOPES.map(str::to_owned).into()
        } else {
            vec!["read".into()]
        }
    }
    pub(super) fn scope(&self) -> &'static str {
        if self.slack() {
            "search:read.public,channels:history"
        } else {
            "read"
        }
    }
    pub(super) fn identity_endpoint(&self) -> String {
        if self.kind == "slack-confidential-v1" {
            "https://slack.com/api/auth.test".into()
        } else {
            format!("{}/api/auth.test", self.issuer)
        }
    }
}

pub(super) fn slack_id(value: &str, prefixes: &[u8]) -> bool {
    (2..=64).contains(&value.len())
        && prefixes.contains(&value.as_bytes()[0])
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

pub(super) fn validate(p: &Profile) -> Result<()> {
    if !identifier(&p.id)
        || !identifier(&p.redirect_profile_id)
        || p.client_generation == 0
        || p.client_generation > i64::MAX as u64
        || p.client_id.is_empty()
        || p.client_id.len() > 256
        || !p.client_id.bytes().all(|b| (0x21..=0x7e).contains(&b))
        || !slack_id(&p.expected_workspace, b"T")
        || !slack_id(&p.expected_user, b"UW")
        || !p.selected_tools.is_empty()
    {
        return Err(Error("invalid_profile"));
    }
    https(&p.redirect_uri, "/oauth/callback")?;
    endpoints(p)
}

fn endpoints(p: &Profile) -> Result<()> {
    if p.kind == "slack-confidential-v1" {
        if p.issuer != "https://mcp.slack.com"
            || p.resource != "https://mcp.slack.com/mcp"
            || p.authorization_endpoint != "https://slack.com/oauth/v2_user/authorize"
            || p.token_endpoint != "https://slack.com/api/oauth.v2.user.access"
        {
            return Err(Error("invalid_profile"));
        }
        return Ok(());
    }
    let origin = endpoint(&p.issuer, "/")?.origin();
    if p.issuer != origin.ascii_serialization() {
        return Err(Error("invalid_profile"));
    }
    for (url, path) in [
        (&p.resource, "/mcp"),
        (&p.authorization_endpoint, "/oauth/v2_user/authorize"),
        (&p.token_endpoint, "/api/oauth.v2.user.access"),
    ] {
        if endpoint(url, path)?.origin() != origin {
            return Err(Error("invalid_profile"));
        }
    }
    Ok(())
}
