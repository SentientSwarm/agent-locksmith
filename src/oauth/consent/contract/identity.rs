use super::{
    super::{Error, Result, config::Profile, parse, token, token_io, wire},
    Subject,
};
use secrecy::ExposeSecret;
use serde_json::Value;
use std::time::Duration;

pub(in crate::oauth::consent) async fn verify(
    w: &wire::Wire<'_>,
    p: &Profile,
    token: &token::Token,
    old: Option<&token::Token>,
) -> Result<Subject> {
    w.enter("identity");
    w.check().await?;
    let value = response(p, token).await?;
    w.check().await?;
    token.screen(&value)?;
    if let Some(old) = old {
        old.screen(&value)?;
    }
    let c = p.contract.as_ref().ok_or(Error("invalid_profile"))?;
    let slack = c.identity.response == "slack-auth-test-v1";
    if !value.is_object()
        || ["error", "error_description", "error_uri"]
            .iter()
            .any(|k| value.get(k).is_some())
        || (slack && value.get("ok") != Some(&Value::Bool(true)))
        || (!slack && value.get("ok").is_some())
    {
        return Err(Error("identity_mismatch"));
    }
    super::token::echoes(p, &value)?;
    c.subject.observe(&value, slack)
}
async fn response(p: &Profile, token: &token::Token) -> Result<Value> {
    let c = p.contract.as_ref().ok_or(Error("invalid_profile"))?;
    let client = token::client(p)?;
    let request = match c.identity.method.as_str() {
        "get" => client.get(&c.identity.endpoint),
        "post" => client.post(&c.identity.endpoint),
        _ => return Err(Error("invalid_profile")),
    };
    let mut r = request
        .timeout(Duration::from_secs(5))
        .bearer_auth(token.access.expose_secret())
        .send()
        .await
        .map_err(token_io::error)?;
    if r.status() != reqwest::StatusCode::OK || r.content_length().is_some_and(|n| n > 65536) {
        return Err(Error("identity_mismatch"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(token_io::error)? {
        if bytes.len() + chunk.len() > 65536 {
            return Err(Error("token_body_limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    parse(&bytes)
}
