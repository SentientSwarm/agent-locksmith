use super::{Error, Result, config::Profile, parse};
use serde_json::Value;

pub(super) fn error(error: reqwest::Error) -> Error {
    Error(if error.is_timeout() {
        "deadline"
    } else {
        "http"
    })
}

pub(super) async fn post(
    p: &Profile,
    client: &reqwest::Client,
    form: &[(&str, &str)],
) -> Result<(reqwest::StatusCode, Vec<u8>)> {
    let mut response = client
        .post(&p.token_endpoint)
        .form(form)
        .send()
        .await
        .map_err(error)?;
    let status = response.status();
    if response.content_length().is_some_and(|n| n > 65536) {
        return Err(Error("token_body_limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(error)? {
        if bytes.len() + chunk.len() > 65536 {
            return Err(Error("token_body_limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}

use super::token::{Token, decode};
use secrecy::ExposeSecret;
pub(super) fn checked_decode(p: &Profile, bytes: &[u8], known: Option<&str>) -> Result<Token> {
    let token = decode(p, bytes)?;
    if known.is_some_and(|s| {
        token.access.expose_secret().contains(s)
            || token
                .refresh
                .as_ref()
                .is_some_and(|r| r.expose_secret().contains(s))
    }) {
        return Err(Error("secret_echo"));
    }
    Ok(token)
}

pub(super) fn refreshed(
    p: &Profile,
    status: reqwest::StatusCode,
    bytes: &[u8],
    old: &Token,
    client_secret: Option<&str>,
) -> Result<Token> {
    refresh_status(status, bytes)?;
    if (p.slack() || p.custom())
        && parse(bytes)?
            .get("refresh_token")
            .is_some_and(Value::is_null)
    {
        return Err(Error("refresh_unavailable"));
    }
    let mut token = checked_decode(p, bytes, client_secret)?;
    if token.refresh.is_none() {
        token.refresh = old.refresh.clone();
    }
    Ok(token)
}

fn refresh_status(status: reqwest::StatusCode, bytes: &[u8]) -> Result<()> {
    if status == reqwest::StatusCode::BAD_REQUEST {
        let value = parse(bytes)?;
        if value.is_object()
            && value["error"] == "invalid_grant"
            && ["access_token", "refresh_token", "token_type", "expires_in"]
                .iter()
                .all(|k| value.get(k).is_none())
        {
            return Err(Error("refresh_invalid_grant"));
        }
    }
    if status != reqwest::StatusCode::OK {
        return Err(Error("token_http_refused"));
    }
    Ok(())
}
