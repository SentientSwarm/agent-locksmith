use super::{
    super::{Error, Result, config::Profile, identifier},
    Contract, Subject,
};
use std::collections::HashSet;

pub(in crate::oauth::consent) fn validate(p: &Profile) -> Result<()> {
    let c = p.contract.as_ref().ok_or(Error("invalid_profile"))?;
    if !identifier(&p.id)
        || !identifier(&p.redirect_profile_id)
        || p.client_generation == 0
        || p.client_generation > i64::MAX as u64
        || !text(&p.client_id)
        || !p.expected_workspace.is_empty()
        || !p.expected_user.is_empty()
        || !p.selected_tools.is_empty()
        || c.version != 1
        || c.grant != "authorization_code_s256"
        || c.registration != "pre_registered"
        || !["none", "client_secret_post"].contains(&c.client_auth.as_str())
        || !["issuer_required", "distinct_redirect"].contains(&c.callback.as_str())
        || !["oauth2-bearer-v1", "slack-user-v2"].contains(&c.token_response.as_str())
        || !["get", "post"].contains(&c.identity.method.as_str())
        || !c.scope.valid()
        || !c.subject.valid()
    {
        return Err(Error("invalid_profile"));
    }
    subject(c)?;
    endpoints(p, c)
}
fn subject(c: &Contract) -> Result<()> {
    let matches = match c.subject {
        Subject::UserWorkspace { .. } => {
            ["workspace-user-v1", "slack-auth-test-v1"].contains(&c.identity.response.as_str())
        }
        Subject::ServicePrincipal { .. } => {
            c.identity.response == "service-principal-v1" && c.token_response == "oauth2-bearer-v1"
        }
    };
    if !matches
        || (c.token_response == "slack-user-v2" && c.identity.response != "slack-auth-test-v1")
    {
        return Err(Error("invalid_profile"));
    }
    Ok(())
}
fn endpoints(p: &Profile, c: &Contract) -> Result<()> {
    let mut origins = HashSet::new();
    for origin in &c.approved_origins {
        let url = url(origin)?;
        if url.path() != "/"
            || url.origin().ascii_serialization() != *origin
            || !origins.insert(origin)
        {
            return Err(Error("invalid_profile"));
        }
    }
    if origins.is_empty() || origins.len() > 4 {
        return Err(Error("invalid_profile"));
    }
    for endpoint in [
        &p.issuer,
        &p.authorization_endpoint,
        &p.token_endpoint,
        &p.resource,
        &c.mcp_endpoint,
        &c.identity.endpoint,
    ] {
        if !origins.contains(&url(endpoint)?.origin().ascii_serialization()) {
            return Err(Error("invalid_profile"));
        }
    }
    p.callback_uri()?;
    Ok(())
}
pub(super) fn url(raw: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(raw).map_err(|_| Error("invalid_profile"))?;
    if raw.len() > 2048
        || u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.port() == Some(0)
    {
        return Err(Error("invalid_profile"));
    }
    Ok(u)
}
fn text(v: &str) -> bool {
    !v.is_empty() && v.len() <= 256 && v.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
