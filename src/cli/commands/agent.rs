//! `locksmith agent ...` operator subcommands.

mod oauth;

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

#[derive(Subcommand)]
pub enum AgentCmd {
    /// Inspect or replace finite reviewed native MCP tool grants.
    McpGrants {
        #[command(subcommand)]
        command: super::native_mcp::GrantsCmd,
    },
    /// List all agents.
    List {
        /// Include revoked agents.
        #[arg(long)]
        include_revoked: bool,
    },
    /// Show one agent by public_id or name.
    Get {
        /// Agent public_id (preferred) or name.
        #[arg(allow_hyphen_values = true)]
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
        /// Restrict to these tool names (comma-separated). Omit for no grants; names must already be configured.
        #[arg(long, value_delimiter = ',')]
        allowlist: Option<Vec<String>>,
        /// Block these tool names (comma-separated).
        #[arg(long, value_delimiter = ',')]
        denylist: Option<Vec<String>>,
    },
    /// Modify an agent's policy in place.
    Modify {
        /// Agent public_id.
        #[arg(allow_hyphen_values = true)]
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
        #[arg(allow_hyphen_values = true)]
        id: String,
        /// Reason recorded in the audit trail (M3).
        #[arg(long)]
        reason: Option<String>,
    },
    /// Bind (or clear) an agent's mTLS cert_identity (#79). Replaces
    /// the M6 onboarding-runbook SQL workaround.
    SetCertIdentity {
        /// Agent public_id.
        #[arg(allow_hyphen_values = true)]
        id: String,
        /// Cert identity to bind (CN, SAN_DNS, or SAN_URI string).
        /// Required unless `--clear` is set.
        #[arg(required_unless_present = "clear")]
        cert_identity: Option<String>,
        /// Clear the existing cert_identity binding.
        #[arg(long, conflicts_with = "cert_identity")]
        clear: bool,
    },
    /// Select an explicit account: auth, None, OAuth, or sealed bearer.
    /// Managed native OAuth uses the separate owner-bound `select-oauth` command.
    SetCredential(SetCredentialArgs),
    /// Delegate an owned managed native OAuth account (named or declared contract) after granting the connection ACL.
    /// Reobserve, review and grant finite tools before using a new native session.
    SelectOauth {
        #[arg(allow_hyphen_values = true)]
        id: String,
        #[arg(allow_hyphen_values = true)]
        registration: String,
        #[arg(long, allow_hyphen_values = true)]
        label: String,
        #[arg(long, allow_hyphen_values = true)]
        if_match: String,
    },
    /// Remove an agent's explicit account binding. Subsequent requests to
    /// this registration are denied until a binding is set again. Idempotent.
    UnsetCredential {
        /// Agent public_id.
        #[arg(allow_hyphen_values = true)]
        id: String,
        /// Registration name.
        registration: String,
    },
    /// Phase G: list all credential overrides for one agent.
    Credentials {
        #[command(subcommand)]
        cmd: AgentCredentialsCmd,
    },
}

#[derive(Subcommand)]
pub enum AgentCredentialsCmd {
    /// List all credential overrides for `<id>`.
    List {
        /// Agent public_id.
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
}

#[derive(Args)]
pub struct SetCredentialArgs {
    /// Agent public_id.
    #[arg(allow_hyphen_values = true)]
    pub id: String,
    /// Registration name (e.g., `lmstudio`, `codex`).
    pub registration: String,
    /// `bearer=<ENV_VAR>` or `header=<Header-Name>:<ENV_VAR>` for
    /// static-credential overrides. The proxy hot path reads the env
    /// var directly when this override is in effect.
    #[arg(
        long,
        conflicts_with_all = ["no_auth", "oauth_session"],
    )]
    pub auth: Option<String>,
    /// Override to no-auth (operator-stated authless on a per-agent
    /// basis). Useful when one agent legitimately bypasses the
    /// upstream's auth shape.
    #[arg(
        long,
        conflicts_with_all = ["auth", "oauth_session"],
    )]
    pub no_auth: bool,
    /// Select a nonempty explicit OAuth session label under the
    /// registration (use `default` literally). Operator must have bootstrapped the
    /// session: `locksmith oauth bootstrap <reg> --label <label> ...`.
    #[arg(
        long,
        conflicts_with_all = ["auth", "no_auth"],
    )]
    pub oauth_session: Option<String>,
    /// Read a bearer value from stdin and seal it; never pass values in argv.
    #[arg(long, conflicts_with_all=["auth","no_auth","oauth_session","stored_bearer_ref"])]
    pub stored_bearer_stdin: bool,
    /// Explicitly select an existing live sealed bearer reference.
    #[arg(long, conflicts_with_all=["auth","no_auth","oauth_session","stored_bearer_stdin"])]
    pub stored_bearer_ref: Option<String>,
    /// Select a broker route: Locksmith sends the route's broker key and
    /// the broker picks the account.
    #[arg(long, conflicts_with_all=["auth","no_auth","oauth_session","stored_bearer_stdin","stored_bearer_ref"])]
    pub broker: bool,
}

pub async fn run(client: &CliClient, format: Format, cmd: AgentCmd) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    match cmd {
        AgentCmd::McpGrants { command } => {
            return super::native_mcp::grants(client, format, command).await;
        }
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
            let mut body = json!({});
            if let Some(value) = option_replace(allowlist) {
                body["allowlist"] = json!(value);
            }
            if let Some(value) = option_replace(denylist) {
                body["denylist"] = json!(value);
            }
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
        AgentCmd::SetCertIdentity {
            id,
            cert_identity,
            clear,
        } => {
            // clap's `required_unless_present`/`conflicts_with` pin the
            // cert_identity-vs-`--clear` invariant at parse time. We
            // also accept the project-wide "-" sentinel for clear
            // (matches `--allowlist -` from `agent modify`).
            let cleared = clear || cert_identity.as_deref() == Some("-");
            let body = if cleared {
                json!({ "cert_identity": Value::Null })
            } else {
                json!({ "cert_identity": cert_identity })
            };
            client
                .unit(
                    "PATCH",
                    &format!("/admin/operator/agents/{id}/cert_identity"),
                    Auth::Operator(&token),
                    Some(&body),
                )
                .await?;
        }
        AgentCmd::SelectOauth {
            id,
            registration,
            label,
            if_match,
        } => {
            let value: Value = client
                .json_body_if_match(
                    "PUT",
                    &format!("/admin/operator/agents/{id}/oauth-selection/{registration}"),
                    Auth::Operator(&token),
                    Some(&json!({"label":label})),
                    &if_match,
                )
                .await?;
            print(&value, format);
        }
        AgentCmd::SetCredential(args) => {
            if args.stored_bearer_stdin {
                return super::native_mcp::ingest(client, format, &args.id, &args.registration)
                    .await;
            }
            let auth_spec = if let Some(label) = &args.oauth_session {
                oauth::selection(client, &token, &args.registration, label).await?
            } else {
                build_auth_spec(&args)?
            };
            let mut body = json!({"auth_spec": auth_spec});
            if args.stored_bearer_ref.is_some() {
                body["require_live_bearer"] = true.into();
            }
            let resp: Value = client
                .json(
                    "PUT",
                    &format!(
                        "/admin/operator/agents/{}/credentials/{}",
                        args.id, args.registration
                    ),
                    Auth::Operator(&token),
                    Some(&body),
                )
                .await?;
            print(&resp, format);
        }
        AgentCmd::UnsetCredential { id, registration } => {
            client
                .unit(
                    "DELETE",
                    &format!("/admin/operator/agents/{id}/credentials/{registration}"),
                    Auth::Operator(&token),
                    None,
                )
                .await?;
            print(
                &json!({
                    "agent": id,
                    "registration": registration,
                    "removed": true,
                }),
                format,
            );
        }
        AgentCmd::Credentials { cmd } => match cmd {
            AgentCredentialsCmd::List { id } => {
                let resp: Value = client
                    .json(
                        "GET",
                        &format!("/admin/operator/agents/{id}/credentials"),
                        Auth::Operator(&token),
                        None,
                    )
                    .await?;
                print(&resp["overrides"], format);
            }
        },
    }
    Ok(())
}

/// Translate the CLI's `--auth` / `--no-auth` / `--oauth-session`
/// flags into the canonical `AuthSpec` JSON shape that the admin
/// endpoint persists. Returns a usage error on conflicting / missing
/// flags. Mirrors registrations' AuthSpec wire form so operator
/// expectations carry across `locksmith {model,tool} put` and the
/// new `agent set-credential`.
fn build_auth_spec(args: &SetCredentialArgs) -> Result<Value, CliError> {
    if let Some(secret_ref) = &args.stored_bearer_ref {
        return Ok(json!({"kind":"stored_bearer","secret_ref":secret_ref}));
    }
    if args.no_auth {
        return Ok(json!({"kind": "none"}));
    }
    if args.broker {
        return Ok(json!({"kind": "broker"}));
    }
    let auth = args.auth.as_deref().ok_or_else(|| {
        CliError::Usage(
            "must provide one of: --auth bearer=ENV, --auth header=H:ENV, --no-auth, --broker, --oauth-session LABEL".into(),
        )
    })?;
    if let Some(env_var) = auth.strip_prefix("bearer=") {
        if env_var.is_empty() {
            return Err(CliError::Usage(
                "--auth bearer= requires an env var name".into(),
            ));
        }
        Ok(json!({"kind": "bearer", "env_var": env_var}))
    } else if let Some(rest) = auth.strip_prefix("header=") {
        let (header, env_var) = rest.split_once(':').ok_or_else(|| {
            CliError::Usage("--auth header= requires <Header-Name>:<ENV_VAR>".into())
        })?;
        if header.is_empty() || env_var.is_empty() {
            return Err(CliError::Usage(
                "--auth header= requires non-empty header and env var".into(),
            ));
        }
        Ok(json!({"kind": "header", "header": header, "env_var": env_var}))
    } else {
        Err(CliError::Usage(format!(
            "--auth must start with 'bearer=' or 'header='; got: {auth:?}"
        )))
    }
}

/// CLI shorthand: `--allowlist -` means "explicitly clear the
/// allowlist (set to empty)"; passing nothing means "do not change".
/// Anything else replaces the field with the provided list.
fn option_replace(input: Option<Vec<String>>) -> Option<Option<Vec<String>>> {
    match input {
        None => None,
        Some(v) if v.len() == 1 && v[0] == "-" => Some(Some(vec![])),
        Some(v) => Some(Some(v)),
    }
}

#[cfg(test)]
mod broker_selection_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: SetCredentialArgs,
    }

    #[test]
    fn broker_flag_selects_the_broker_kind() {
        let cli = Cli::try_parse_from(["x", "agent-id", "pool", "--broker"]).unwrap();
        assert_eq!(
            build_auth_spec(&cli.args).unwrap(),
            json!({"kind": "broker"})
        );
        assert!(Cli::try_parse_from(["x", "a", "pool", "--broker", "--no-auth"]).is_err());
    }
}
