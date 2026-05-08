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
    /// Show OAuth session status for `<name>` [--label <label>].
    Status {
        name: String,
        /// Phase G: session label (defaults to "default"). Use to
        /// inspect a specific per-agent session under a registration.
        #[arg(long)]
        label: Option<String>,
    },
    /// Revoke (delete locally) the OAuth session for `<name>`
    /// [--label <label>]. Idempotent. Does NOT call the provider's
    /// revoke endpoint.
    Revoke {
        name: String,
        /// Phase G: session label (defaults to "default").
        #[arg(long)]
        label: Option<String>,
    },
    /// List all OAuth sessions across all registrations + labels.
    /// Phase G; useful for spotting orphaned per-agent sessions.
    List,
}

#[derive(Args, Debug)]
pub struct BootstrapArgs {
    /// Registration name (must already exist as a kind=tool or
    /// kind=model with an OAuth AuthSpec).
    pub name: String,

    /// Phase G: session label. Defaults to "default" — single shared
    /// session per registration. Use distinct labels (e.g., "hermes",
    /// "openclaw") when bootstrapping per-agent OAuth from different
    /// upstream accounts. See concepts/per-agent-credentials.md for
    /// the single-grant trap explanation.
    #[arg(long)]
    pub label: Option<String>,

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
