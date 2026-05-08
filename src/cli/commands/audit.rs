//! `locksmith audit ...` operator subcommands. Backed by GET
//! /admin/operator/audit on the daemon.

use clap::Subcommand;
use serde_json::Value;

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

#[derive(Subcommand)]
pub enum AuditCmd {
    /// Query the audit log.
    Query {
        /// Filter by agent public_id.
        #[arg(long)]
        agent: Option<String>,
        /// Filter by tool name.
        #[arg(long)]
        tool: Option<String>,
        /// Filter by event class (proxy | operator | security).
        #[arg(long)]
        event_class: Option<String>,
        /// Filter by decision (allowed | denied | error).
        #[arg(long)]
        decision: Option<String>,
        /// Lower bound on event timestamp (unix ms).
        #[arg(long)]
        since_ms: Option<i64>,
        /// Upper bound on event timestamp (unix ms, exclusive).
        #[arg(long)]
        until_ms: Option<i64>,
        /// Page size (default 100).
        #[arg(long)]
        limit: Option<u32>,
        /// Offset into the result set.
        #[arg(long)]
        offset: Option<u32>,
    },
}

pub async fn run(client: &CliClient, format: Format, cmd: AuditCmd) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    match cmd {
        AuditCmd::Query {
            agent,
            tool,
            event_class,
            decision,
            since_ms,
            until_ms,
            limit,
            offset,
        } => {
            let mut qs: Vec<String> = Vec::new();
            if let Some(v) = agent {
                qs.push(format!("agent={v}"));
            }
            if let Some(v) = tool {
                qs.push(format!("tool={v}"));
            }
            if let Some(v) = event_class {
                qs.push(format!("event_class={v}"));
            }
            if let Some(v) = decision {
                qs.push(format!("decision={v}"));
            }
            if let Some(v) = since_ms {
                qs.push(format!("since_ms={v}"));
            }
            if let Some(v) = until_ms {
                qs.push(format!("until_ms={v}"));
            }
            if let Some(v) = limit {
                qs.push(format!("limit={v}"));
            }
            if let Some(v) = offset {
                qs.push(format!("offset={v}"));
            }
            let path = if qs.is_empty() {
                "/admin/operator/audit".to_string()
            } else {
                format!("/admin/operator/audit?{}", qs.join("&"))
            };
            let resp: Value = client
                .json("GET", &path, Auth::Operator(&token), None)
                .await?;
            print(&resp["events"], format);
        }
    }
    Ok(())
}
