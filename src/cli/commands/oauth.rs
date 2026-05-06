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

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

#[derive(Subcommand, Debug)]
pub enum OauthCmd {
    /// Bootstrap a new OAuth session for `<name>` with a
    /// pre-obtained refresh token. v1.0 manual path: complete the
    /// provider's own OAuth flow first (e.g., `gh auth login` for
    /// copilot, `claude auth` for anthropic-oauth) and pass the
    /// refresh token here. Future versions ship the interactive
    /// flow inside this command.
    Bootstrap(BootstrapArgs),
    /// Show OAuth session status for `<name>`.
    Status { name: String },
    /// Revoke (delete locally) the OAuth session for `<name>`.
    /// Idempotent. Does NOT call the provider's revoke endpoint.
    Revoke { name: String },
}

#[derive(Args, Debug)]
pub struct BootstrapArgs {
    /// Registration name (must already exist as a kind=tool or
    /// kind=model with an OAuth AuthSpec).
    pub name: String,

    /// Refresh token obtained out-of-band from the provider's OAuth
    /// flow. WARNING: this argument transits the shell history. Prefer
    /// `--refresh-token-stdin` for production use.
    #[arg(long, conflicts_with = "refresh_token_stdin")]
    pub refresh_token: Option<String>,

    /// Read the refresh token from stdin (one line, trimmed). Use this
    /// in scripts / pipelines to keep the token out of shell history.
    #[arg(long, conflicts_with = "refresh_token")]
    pub refresh_token_stdin: bool,
}

pub async fn run(client: &CliClient, format: Format, cmd: OauthCmd) -> Result<(), CliError> {
    match cmd {
        OauthCmd::Bootstrap(args) => bootstrap(client, format, args).await,
        OauthCmd::Status { name } => status(client, format, &name).await,
        OauthCmd::Revoke { name } => revoke(client, format, &name).await,
    }
}

async fn bootstrap(
    client: &CliClient,
    format: Format,
    args: BootstrapArgs,
) -> Result<(), CliError> {
    let token = match (args.refresh_token, args.refresh_token_stdin) {
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
    let op_token = CliClient::op_token()?;
    let body = json!({"refresh_token": token.trim()});
    let response: Value = client
        .json(
            "POST",
            &format!("/admin/operator/oauth/{}/bootstrap", args.name),
            Auth::Operator(&op_token),
            Some(&body),
        )
        .await?;
    print(&response, format);
    Ok(())
}

async fn status(client: &CliClient, format: Format, name: &str) -> Result<(), CliError> {
    let op_token = CliClient::op_token()?;
    let response: Value = client
        .json(
            "GET",
            &format!("/admin/operator/oauth/{name}"),
            Auth::Operator(&op_token),
            None,
        )
        .await?;
    print(&response, format);
    Ok(())
}

async fn revoke(client: &CliClient, format: Format, name: &str) -> Result<(), CliError> {
    let op_token = CliClient::op_token()?;
    client
        .unit(
            "DELETE",
            &format!("/admin/operator/oauth/{name}"),
            Auth::Operator(&op_token),
            None,
        )
        .await?;
    print(&json!({"name": name, "revoked": true}), format);
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
