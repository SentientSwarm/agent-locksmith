//! `locksmith oauth` — OAuth session management. Phase F.4.
//!
//! Three subcommands:
//!
//! - `bootstrap <name> --refresh-token <token>` — supply a refresh
//!   token obtained via the provider's own OAuth flow. v1.0 manual
//!   path; v1.1+ adds interactive PKCE / device-code.
//! - `status <name>` — show whether a session is bootstrapped, when
//!   the access token expires, and whether refresh has degraded.
//! - `revoke <name>` — clear locally-stored tokens.
//!
//! All three talk to admin UDS (or admin HTTPS via `--admin-url`).
//! Operator-credentialed.

use serde_json::{Value, json};

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

mod args;
pub use args::{BootstrapArgs, OauthCmd};

pub async fn run(client: &CliClient, format: Format, cmd: OauthCmd) -> Result<(), CliError> {
    match cmd {
        OauthCmd::Connect {
            name,
            label,
            profile,
            client_generation,
            redirect_profile,
            expected_config_revision,
        } => {
            component(&name)?;
            component(&label)?;
            let op = CliClient::op_token()?;
            let body = json!({"session_label":label,"auth_profile_id":profile,"client_generation":client_generation,"redirect_profile_id":redirect_profile,"expected_config_revision":expected_config_revision,"requested_scopes":["read"]});
            let result: Value = client
                .json(
                    "POST",
                    &format!("/admin/operator/tools/{name}/oauth/attempts"),
                    Auth::Operator(&op),
                    Some(&body),
                )
                .await?;
            print(&result, format);
            Ok(())
        }
        OauthCmd::AttemptStatus { name, attempt } => {
            consent_request(client, format, &name, "attempts", &attempt, false, None).await
        }
        OauthCmd::Cancel { name, attempt } => {
            consent_request(client, format, &name, "attempts", &attempt, true, None).await
        }
        OauthCmd::AccountStatus { name, label } => {
            consent_request(client, format, &name, "accounts", &label, false, None).await
        }
        OauthCmd::Disconnect {
            name,
            label,
            if_match,
        } => {
            consent_request(
                client,
                format,
                &name,
                "accounts",
                &label,
                true,
                Some(&if_match),
            )
            .await
        }
        OauthCmd::Refresh {
            name,
            label,
            if_match,
        } => {
            component(&name)?;
            component(&label)?;
            let op = CliClient::op_token()?;
            let result: Value = client
                .json_if_match(
                    "POST",
                    &format!("/admin/operator/tools/{name}/oauth/accounts/{label}/refresh"),
                    Auth::Operator(&op),
                    &if_match,
                )
                .await?;
            print(&result, format);
            Ok(())
        }
        OauthCmd::Bootstrap(args) => bootstrap(client, format, args).await,
        OauthCmd::Status { name, label } => status(client, format, &name, label.as_deref()).await,
        OauthCmd::Revoke { name, label } => revoke(client, format, &name, label.as_deref()).await,
        OauthCmd::List => list(client, format).await,
    }
}

/// Append `?label=<label>` to `path` when a non-default label is
/// supplied. Skipping the query string for the default case keeps
/// audit-grep patterns and curl recipes uniform with pre-Phase-G
/// deployments.
///
/// Labels MUST be ascii alphanumeric / `-` / `_` (validated here);
/// anything else is a usage error. This bounds the query-string
/// shape so we can avoid pulling in a URL-encoder crate.
fn with_label_query(path: &str, label: Option<&str>) -> Result<String, CliError> {
    match label {
        Some(l) if l != "default" => {
            if !l
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(CliError::Usage(format!(
                    "session label must be ascii alphanumeric / '-' / '_'; got: {l:?}"
                )));
            }
            Ok(format!(
                "{}{}label={}",
                path,
                if path.contains('?') { '&' } else { '?' },
                l
            ))
        }
        _ => Ok(path.to_string()),
    }
}

async fn bootstrap(
    client: &CliClient,
    format: Format,
    args: BootstrapArgs,
) -> Result<(), CliError> {
    let token = bootstrap_token(args.refresh_token, args.refresh_token_stdin)?;
    let op_token = CliClient::op_token()?;
    let body = json!({"refresh_token": token.trim()});
    let path = with_label_query(
        &format!("/admin/operator/oauth/{}/bootstrap", args.name),
        args.label.as_deref(),
    )?;
    let response: Value = client
        .json("POST", &path, Auth::Operator(&op_token), Some(&body))
        .await?;
    print(&response, format);
    Ok(())
}

async fn status(
    client: &CliClient,
    format: Format,
    name: &str,
    label: Option<&str>,
) -> Result<(), CliError> {
    let op_token = CliClient::op_token()?;
    let path = with_label_query(&format!("/admin/operator/oauth/{name}"), label)?;
    let response: Value = client
        .json("GET", &path, Auth::Operator(&op_token), None)
        .await?;
    print(&response, format);
    Ok(())
}

async fn revoke(
    client: &CliClient,
    format: Format,
    name: &str,
    label: Option<&str>,
) -> Result<(), CliError> {
    let op_token = CliClient::op_token()?;
    let path = with_label_query(&format!("/admin/operator/oauth/{name}"), label)?;
    client
        .unit("DELETE", &path, Auth::Operator(&op_token), None)
        .await?;
    print(
        &json!({
            "name": name,
            "label": label.unwrap_or("default"),
            "revoked": true,
        }),
        format,
    );
    Ok(())
}

async fn list(client: &CliClient, format: Format) -> Result<(), CliError> {
    let op_token = CliClient::op_token()?;
    let response: Value = client
        .json(
            "GET",
            "/admin/operator/oauth",
            Auth::Operator(&op_token),
            None,
        )
        .await?;
    print(&response["sessions"], format);
    Ok(())
}

fn read_stdin_token() -> Result<String, CliError> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| CliError::Usage(format!("read stdin: {e}")))?;
    Ok(buf)
}

fn bootstrap_token(token: Option<String>, stdin: bool) -> Result<String, CliError> {
    let token = match (token, stdin) {
        (Some(t), false) => t,
        (None, true) => read_stdin_token()?,
        (None, false) => {
            return Err(CliError::Usage(
                "must provide either --refresh-token <TOKEN> or --refresh-token-stdin".into(),
            ));
        }
        (Some(_), true) => unreachable!("clap conflicts_with prevents this"),
    };
    if token.trim().is_empty() {
        return Err(CliError::Usage("refresh token is empty".into()));
    }
    Ok(token)
}

fn component(value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(CliError::Usage("invalid consent path component".into()));
    }
    Ok(())
}
async fn consent_request(
    client: &CliClient,
    format: Format,
    name: &str,
    kind: &str,
    id: &str,
    delete: bool,
    expected: Option<&str>,
) -> Result<(), CliError> {
    component(name)?;
    component(id)?;
    let op = CliClient::op_token()?;
    let path = format!("/admin/operator/tools/{name}/oauth/{kind}/{id}");
    let result: Value = if let Some(expected) = expected {
        client
            .json_if_match("DELETE", &path, Auth::Operator(&op), expected)
            .await?
    } else if delete {
        client
            .unit("DELETE", &path, Auth::Operator(&op), None)
            .await?;
        json!({"canceled":true})
    } else {
        client.json("GET", &path, Auth::Operator(&op), None).await?
    };
    print(&result, format);
    Ok(())
}
