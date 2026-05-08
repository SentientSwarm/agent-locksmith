//! `locksmith bootstrap ...` operator subcommands.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

#[derive(Subcommand)]
pub enum BootstrapCmd {
    /// Mint a new bootstrap token. Returned cleartext exactly once.
    Mint {
        /// Restrict consuming agents to these tools (comma-separated).
        #[arg(long, value_delimiter = ',')]
        allowlist: Option<Vec<String>>,
        /// Single-use (default true). Pass `--reusable` to allow multiple consumes.
        #[arg(long)]
        reusable: bool,
        /// Unix epoch seconds at which the token expires.
        #[arg(long)]
        expires_at: Option<i64>,
    },
    /// List bootstrap tokens.
    List,
    /// Revoke a bootstrap token by public_id.
    Revoke {
        /// Bootstrap token public_id.
        id: String,
    },
}

pub async fn run(client: &CliClient, format: Format, cmd: BootstrapCmd) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    match cmd {
        BootstrapCmd::Mint {
            allowlist,
            reusable,
            expires_at,
        } => {
            let body = json!({
                "tool_allowlist": allowlist,
                "single_use": !reusable,
                "expires_at": expires_at,
            });
            let resp: Value = client
                .json(
                    "POST",
                    "/admin/operator/bootstrap_tokens",
                    Auth::Operator(&token),
                    Some(&body),
                )
                .await?;
            print(&resp, format);
        }
        BootstrapCmd::List => {
            let resp: Value = client
                .json(
                    "GET",
                    "/admin/operator/bootstrap_tokens",
                    Auth::Operator(&token),
                    None,
                )
                .await?;
            print(&resp["tokens"], format);
        }
        BootstrapCmd::Revoke { id } => {
            client
                .unit(
                    "POST",
                    &format!("/admin/operator/bootstrap_tokens/{id}/revoke"),
                    Auth::Operator(&token),
                    None,
                )
                .await?;
        }
    }
    Ok(())
}
