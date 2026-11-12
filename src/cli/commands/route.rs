//! `locksmith route ...` — brokered routes phase 2: declared backends and
//! switching a route's active backend.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::client::{Auth, CliClient, CliError};
use crate::commands::registration::{parse_auth_spec, read_upstream_ca_file};
use crate::output::{Format, print};

#[derive(Subcommand)]
pub enum RouteCmd {
    /// Manage a route's declared backends.
    Backend {
        #[command(subcommand)]
        cmd: BackendCmd,
    },
    /// Make a declared backend the route's active backend. Grants stay;
    /// bindings move with the backend.
    Switch {
        /// Route (registration) name.
        route: String,
        /// Backend to activate (`primary` is the route's original backend).
        #[arg(long)]
        backend: String,
        /// The route revision from `route backend list` (optimistic lock).
        #[arg(long)]
        if_match: i64,
    },
}

#[derive(Subcommand)]
pub enum BackendCmd {
    /// List a route's backends, its active backend and revision.
    List { route: String },
    /// Show one declared backend.
    Get { route: String, backend: String },
    /// Declare or replace an inactive backend. Moving its destination
    /// clears the bindings stashed for it.
    Put {
        route: String,
        backend: String,
        #[arg(long)]
        upstream: String,
        #[arg(long, value_parser = ["direct", "proxied"])]
        egress: Option<String>,
        /// PEM file with the backend's trust anchors (`-` reads stdin).
        #[arg(long)]
        upstream_ca_file: Option<std::path::PathBuf>,
        /// Auth template: `none`, `header:NAME=ENV`, `bearer=ENV`, etc.
        #[arg(long)]
        auth: String,
    },
    /// Delete an inactive backend and its stashed bindings.
    Delete { route: String, backend: String },
}

fn path(route: &str, rest: &str) -> String {
    format!("/admin/operator/routes/{route}{rest}")
}

pub async fn run(client: &CliClient, format: Format, cmd: RouteCmd) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    let op = Auth::Operator(&token);
    match cmd {
        RouteCmd::Switch {
            route,
            backend,
            if_match,
        } => {
            let body = json!({ "backend": backend });
            let resp: Value = client
                .json_body_if_match(
                    "POST",
                    &path(&route, "/switch"),
                    op,
                    Some(&body),
                    &if_match.to_string(),
                )
                .await?;
            print(&resp, format);
        }
        RouteCmd::Backend { cmd } => match cmd {
            BackendCmd::List { route } => {
                let resp: Value = client
                    .json("GET", &path(&route, "/backends"), op, None)
                    .await?;
                print(&resp, format);
            }
            BackendCmd::Get { route, backend } => {
                let p = path(&route, &format!("/backends/{backend}"));
                let resp: Value = client.json("GET", &p, op, None).await?;
                print(&resp, format);
            }
            BackendCmd::Put {
                route,
                backend,
                upstream,
                egress,
                upstream_ca_file,
                auth,
            } => {
                let auth = parse_auth_spec(Some(&auth))?.unwrap_or(json!({ "kind": "none" }));
                let mut body = json!({ "upstream": upstream, "auth": auth });
                if let Some(e) = egress {
                    body["egress"] = json!(e);
                }
                if let Some(f) = upstream_ca_file {
                    body["upstream_ca_pem"] = json!(read_upstream_ca_file(&f)?);
                }
                let p = path(&route, &format!("/backends/{backend}"));
                let resp: Value = client.json("PUT", &p, op, Some(&body)).await?;
                print(&resp, format);
            }
            BackendCmd::Delete { route, backend } => {
                let p = path(&route, &format!("/backends/{backend}"));
                client.unit("DELETE", &p, op, None).await?;
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: RouteCmd,
    }

    #[test]
    fn route_switch_requires_backend_and_if_match() {
        assert!(Cli::try_parse_from(["t", "switch", "r", "--backend", "b"]).is_err());
        assert!(Cli::try_parse_from(["t", "switch", "r", "--if-match", "3"]).is_err());
        let ok = Cli::try_parse_from(["t", "switch", "r", "--backend", "b", "--if-match", "3"]);
        assert!(matches!(
            ok.map(|c| c.cmd),
            Ok(RouteCmd::Switch { if_match: 3, .. })
        ));
        assert!(
            Cli::try_parse_from([
                "t",
                "backend",
                "put",
                "r",
                "b",
                "--upstream",
                "https://b.example",
                "--auth",
                "none"
            ])
            .is_ok()
        );
    }
}
