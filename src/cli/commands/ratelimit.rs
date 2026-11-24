//! `locksmith rate-limit ...` — per-agent, per-route rate limits
//! (AGENT-266).

use clap::Subcommand;
use serde_json::{Value, json};

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

#[derive(Subcommand)]
pub enum RateLimitCmd {
    /// Set a route's limit, or one agent's override of it.
    Set {
        route: String,
        /// Requests per minute (token bucket, refilled continuously).
        #[arg(long)]
        rpm: u32,
        /// Requests in flight at once, streamed bodies included.
        #[arg(long)]
        concurrent: Option<u32>,
        /// Agent public id or name; omit for the route default.
        #[arg(long, allow_hyphen_values = true)]
        agent: Option<String>,
    },
    /// List every limit.
    List,
    /// Remove a route's limit, or one agent's override of it.
    Unset {
        route: String,
        #[arg(long, allow_hyphen_values = true)]
        agent: Option<String>,
    },
}

pub async fn run(client: &CliClient, format: Format, cmd: RateLimitCmd) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    let op = Auth::Operator(&token);
    match cmd {
        RateLimitCmd::Set {
            route,
            rpm,
            concurrent,
            agent,
        } => {
            let body = json!({
                "requests_per_minute": rpm,
                "max_concurrent": concurrent,
                "agent": agent,
            });
            let path = format!("/admin/operator/rate-limits/{}", encode(&route));
            let resp: Value = client.json("PUT", &path, op, Some(&body)).await?;
            print(&resp, format);
        }
        RateLimitCmd::List => {
            let resp: Value = client
                .json("GET", "/admin/operator/rate-limits", op, None)
                .await?;
            print(&resp, format);
        }
        RateLimitCmd::Unset { route, agent } => {
            let mut path = format!("/admin/operator/rate-limits/{}", encode(&route));
            if let Some(agent) = agent {
                path.push_str(&format!("?agent={}", encode(&agent)));
            }
            client.unit("DELETE", &path, op, None).await?;
        }
    }
    Ok(())
}

/// Percent-encode everything but RFC 3986 unreserved characters.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
