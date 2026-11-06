//! Strict user-only Slack response. Optional metadata never invents usability.
use super::{
    Error, Result,
    config::Profile,
    now,
    token::{Token, secret},
};
use serde_json::Value;

pub(super) fn outcome(v: &Value) -> Result<()> {
    if !v.is_object() {
        return Err(Error("token_invalid"));
    }
    if v["ok"] == false {
        if ["access_token", "refresh_token", "authed_user", "token_type"]
            .iter()
            .any(|k| v.get(k).is_some())
        {
            return Err(Error("token_invalid"));
        }
        return Err(Error(match v["error"].as_str() {
            Some("invalid_code" | "bad_code_verifier") => "slack_code_refused",
            Some("invalid_client_id" | "bad_client_secret" | "invalid_client") => {
                "slack_client_refused"
            }
            Some("invalid_refresh_token" | "token_revoked" | "token_expired") => {
                "slack_refresh_refused"
            }
            _ => "slack_error_response",
        }));
    }
    if v["ok"] != true || v.get("error").is_some() {
        return Err(Error("token_invalid"));
    }
    Ok(())
}

fn scopes(v: &Value) -> bool {
    let Some(s) = v.as_str() else {
        return false;
    };
    let fields = s.split(',').collect::<Vec<_>>();
    fields.len() == 2 && super::slack::SCOPES.iter().all(|s| fields.contains(s))
}

fn metadata(p: &Profile, v: &Value) -> Result<()> {
    for (key, expected) in [
        ("issuer", &p.issuer),
        ("iss", &p.issuer),
        ("resource", &p.resource),
        ("client_id", &p.client_id),
    ] {
        if v.get(key).is_some_and(|v| v != expected.as_str()) {
            return Err(Error("token_metadata_mismatch"));
        }
    }
    if v["team"]["id"] != p.expected_workspace
        || v["authed_user"]["id"] != p.expected_user
        || !scopes(&v["authed_user"]["scope"])
        || v.get("scope").is_some_and(|s| !scopes(s))
        || v.get("team_id")
            .is_some_and(|s| s != p.expected_workspace.as_str())
        || v.get("user_id")
            .is_some_and(|s| s != p.expected_user.as_str())
    {
        return Err(Error("token_metadata_mismatch"));
    }
    Ok(())
}

pub(super) fn decode(p: &Profile, v: &Value) -> Result<Token> {
    outcome(v)?;
    metadata(p, v)?;
    if v["token_type"] != "user" || v.get("bot_user_id").is_some() {
        return Err(Error("token_invalid"));
    }
    let access = secret(&v["access_token"])?;
    let refresh = v
        .get("refresh_token")
        .filter(|v| !v.is_null())
        .map(secret)
        .transpose()?;
    let expiry = expiry(v)?;
    for key in ["access_token", "refresh_token", "expires_in", "token_type"] {
        if v["authed_user"]
            .get(key)
            .is_some_and(|nested| Some(nested) != v.get(key))
        {
            return Err(Error("token_metadata_mismatch"));
        }
    }
    Ok(Token {
        access,
        refresh,
        expiry,
        scope_echoed: true,
    })
}

fn expiry(v: &Value) -> Result<Option<i64>> {
    v.get("expires_in")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_u64()
                .filter(|n| *n > 0 && *n <= 31536000)
                .and_then(|n| now().checked_add(n as i64))
                .ok_or(Error("token_invalid"))
        })
        .transpose()
}
