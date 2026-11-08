use super::{
    super::{
        Error, Result,
        config::Profile,
        now,
        token::{Token, secret},
    },
    Contract,
};
use serde_json::Value;

pub(in crate::oauth::consent) fn decode(p: &Profile, v: &Value) -> Result<Token> {
    let c = p.contract.as_ref().ok_or(Error("invalid_profile"))?;
    outcome(v, c.token_response == "slack-user-v2")?;
    echoes(p, v)?;
    let scope = if c.token_response == "slack-user-v2" {
        super::slack::check(c, v)?
    } else {
        if !v
            .get("token_type")
            .and_then(Value::as_str)
            .is_some_and(|s| s.eq_ignore_ascii_case("Bearer"))
        {
            return Err(Error("token_response_refused"));
        }
        c.scope.evidence(v.get("scope"))?
    };
    credentials(c, v, scope)
}
fn credentials(c: &Contract, v: &Value, scope: String) -> Result<Token> {
    let nullable = c.token_response == "slack-user-v2";
    let refresh = match v.get("refresh_token") {
        None => None,
        Some(Value::Null) if nullable => None,
        Some(v) => Some(secret(v)?),
    };
    let expiry = match v.get("expires_in") {
        None => None,
        Some(Value::Null) if nullable => None,
        Some(v) => Some(
            v.as_u64()
                .filter(|n| *n > 0 && *n <= 31536000)
                .and_then(|n| now().checked_add(n as i64))
                .ok_or(Error("token_response_refused"))?,
        ),
    };
    Ok(Token {
        access: secret(
            v.get("access_token")
                .ok_or(Error("token_response_refused"))?,
        )?,
        refresh,
        expiry,
        scope_echoed: true,
        granted_scope: Some(scope),
    })
}
pub(super) fn outcome(v: &Value, slack: bool) -> Result<()> {
    if !v.is_object()
        || ["error", "error_description", "error_uri"]
            .iter()
            .any(|k| v.get(k).is_some())
        || v.get("ok").is_some_and(|v| v != true)
        || (!slack && v.get("ok").is_some())
    {
        return Err(Error("token_response_refused"));
    }
    Ok(())
}
pub(super) fn echoes(p: &Profile, v: &Value) -> Result<()> {
    for (key, expected) in [
        ("issuer", &p.issuer),
        ("iss", &p.issuer),
        ("resource", &p.resource),
        ("client_id", &p.client_id),
    ] {
        if let Some(actual) = v.get(key)
            && actual.as_str() != Some(expected)
        {
            return Err(Error("token_metadata_mismatch"));
        }
    }
    let c = p.contract.as_ref().unwrap();
    c.subject.echoes(v)?;
    if let Some(scope) = v.get("authed_user").and_then(|u| u.get("scope")) {
        c.scope.evidence(Some(scope))?;
    }
    super::super::slack_metadata::echoes(v)
}
