//! Slack's fixed authenticated identity endpoint; no token-claim inference.
use super::{Error, Result, config::Profile, token, wire};

pub(super) async fn verify(
    w: &wire::Wire<'_>,
    p: &Profile,
    token: &token::Token,
    old: Option<&token::Token>,
) -> Result<()> {
    use secrecy::ExposeSecret;
    w.enter("identity");
    w.check().await?;
    let value = response(p, token.access.expose_secret()).await?;
    token.screen(&value)?;
    if let Some(old) = old {
        old.screen(&value)?;
    }
    super::slack_token::outcome(&value)?;
    if value["team_id"] != p.expected_workspace
        || value["user_id"] != p.expected_user
        || value.get("bot_id").is_some()
    {
        return Err(Error("identity_mismatch"));
    }
    w.check().await
}

async fn response(p: &Profile, bearer: &str) -> Result<serde_json::Value> {
    let response = token::client(p)?
        .post(p.identity_endpoint())
        .timeout(std::time::Duration::from_secs(5))
        .bearer_auth(bearer)
        .send()
        .await
        .map_err(super::token_io::error)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(Error("identity_http_refused"));
    }
    body(response).await
}

async fn body(mut response: reqwest::Response) -> Result<serde_json::Value> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(super::token_io::error)? {
        if bytes.len() + chunk.len() > 65536 {
            return Err(Error("identity_body_limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    super::parse(&bytes)
}
