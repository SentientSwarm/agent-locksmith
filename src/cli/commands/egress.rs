//! `locksmith egress ...` — the egress policy Locksmith wants enforced
//! (AGENT-137).

use clap::Subcommand;
use serde_json::Value;

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

#[derive(Subcommand)]
pub enum EgressCmd {
    /// Hosts reached by proxied routes, grouped by host and port.
    Policy {
        /// Print a Pipelock `api_allowlist` fragment instead of JSON.
        #[arg(long)]
        pipelock: bool,
    },
}

pub async fn run(client: &CliClient, format: Format, cmd: EgressCmd) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    let op = Auth::Operator(&token);
    match cmd {
        EgressCmd::Policy { pipelock } => {
            let resp: Value = client
                .json("GET", "/admin/operator/egress/policy", op, None)
                .await?;
            if pipelock {
                print!(
                    "{}",
                    agent_locksmith::admin::egress_policy::pipelock_allowlist(&resp)
                );
            } else {
                print(&resp, format);
            }
        }
    }
    Ok(())
}
