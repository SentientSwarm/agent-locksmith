//! Agent self-service commands: `status`, `rotate`. Authenticate via
//! the agent's own token (LOCKSMITH_AGENT_TOKEN).

use serde_json::{Value, json};

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

pub async fn status(client: &CliClient, format: Format) -> Result<(), CliError> {
    let token = CliClient::agent_token()?;
    let resp: Value = client
        .json("GET", "/admin/agent/status", Auth::Agent(&token), None)
        .await?;
    print(&resp, format);
    Ok(())
}

pub async fn rotate(
    client: &CliClient,
    format: Format,
    current_secret: Option<String>,
) -> Result<(), CliError> {
    let token = CliClient::agent_token()?;
    // If --current-secret wasn't given, derive it from the token. The
    // wire format is `lk_<id>.<secret>`.
    let secret = match current_secret {
        Some(s) => s,
        None => token
            .split_once('.')
            .map(|(_id, sec)| sec.to_string())
            .ok_or(CliError::MalformedAgentToken)?,
    };
    let body = json!({ "current_secret": secret });
    let resp: Value = client
        .json(
            "POST",
            "/admin/agent/rotate",
            Auth::Agent(&token),
            Some(&body),
        )
        .await?;
    print(&resp, format);
    Ok(())
}
