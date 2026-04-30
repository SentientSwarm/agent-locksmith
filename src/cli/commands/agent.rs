//! `locksmith agent ...` operator subcommands.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

#[derive(Subcommand)]
pub enum AgentCmd {
    /// List all agents.
    List {
        /// Include revoked agents.
        #[arg(long)]
        include_revoked: bool,
    },
    /// Show one agent by public_id or name.
    Get {
        /// Agent public_id (preferred) or name.
        id: String,
    },
    /// Register a new agent and return its token (operator path).
    Register {
        /// Agent name (must be unique).
        #[arg(long)]
        name: String,
        /// Optional human-readable description.
        #[arg(long)]
        description: Option<String>,
        /// Restrict to these tool names (comma-separated). Omit to allow all.
        #[arg(long, value_delimiter = ',')]
        allowlist: Option<Vec<String>>,
        /// Block these tool names (comma-separated).
        #[arg(long, value_delimiter = ',')]
        denylist: Option<Vec<String>>,
    },
    /// Modify an agent's policy in place.
    Modify {
        /// Agent public_id.
        id: String,
        /// Replace allowlist with this set (comma-separated). Use `-` to clear.
        #[arg(long, value_delimiter = ',')]
        allowlist: Option<Vec<String>>,
        /// Replace denylist with this set (comma-separated). Use `-` to clear.
        #[arg(long, value_delimiter = ',')]
        denylist: Option<Vec<String>>,
    },
    /// Revoke an agent (soft-delete; future auth attempts fail 401).
    Revoke {
        /// Agent public_id.
        id: String,
        /// Reason recorded in the audit trail (M3).
        #[arg(long)]
        reason: Option<String>,
    },
}

pub async fn run(client: &CliClient, format: Format, cmd: AgentCmd) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    match cmd {
        AgentCmd::List { include_revoked } => {
            let path = if include_revoked {
                "/admin/operator/agents?include_revoked=true"
            } else {
                "/admin/operator/agents"
            };
            let resp: Value = client
                .json("GET", path, Auth::Operator(&token), None)
                .await?;
            // Pretty-print the agents array.
            print(&resp["agents"], format);
        }
        AgentCmd::Get { id } => {
            let resp: Value = client
                .json(
                    "GET",
                    &format!("/admin/operator/agents/{id}"),
                    Auth::Operator(&token),
                    None,
                )
                .await?;
            print(&resp, format);
        }
        AgentCmd::Register {
            name,
            description,
            allowlist,
            denylist,
        } => {
            let body = json!({
                "name": name,
                "description": description,
                "allowlist": allowlist,
                "denylist": denylist,
            });
            let resp: Value = client
                .json(
                    "POST",
                    "/admin/operator/agents",
                    Auth::Operator(&token),
                    Some(&body),
                )
                .await?;
            print(&resp, format);
        }
        AgentCmd::Modify {
            id,
            allowlist,
            denylist,
        } => {
            let body = json!({
                "allowlist": option_replace(allowlist),
                "denylist": option_replace(denylist),
            });
            client
                .unit(
                    "PATCH",
                    &format!("/admin/operator/agents/{id}"),
                    Auth::Operator(&token),
                    Some(&body),
                )
                .await?;
        }
        AgentCmd::Revoke { id, reason: _ } => {
            client
                .unit(
                    "POST",
                    &format!("/admin/operator/agents/{id}/revoke"),
                    Auth::Operator(&token),
                    None,
                )
                .await?;
        }
    }
    Ok(())
}

/// CLI shorthand: `--allowlist -` means "explicitly clear the
/// allowlist (set to empty)"; passing nothing means "do not change".
/// Anything else replaces the field with the provided list.
fn option_replace(input: Option<Vec<String>>) -> Option<Option<Vec<String>>> {
    match input {
        None => None,
        Some(v) if v.len() == 1 && v[0] == "-" => Some(None),
        Some(v) => Some(Some(v)),
    }
}
