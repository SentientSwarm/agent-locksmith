//! `locksmith tool ...` subcommands. Operator-scoped lists today; M3
//! adds proxy stats per tool.

use clap::Subcommand;
use serde_json::Value;

use crate::client::{Auth, CliClient, CliError};
use crate::output::{Format, print};

#[derive(Subcommand)]
pub enum ToolCmd {
    /// List configured tools.
    List,
}

pub async fn run(client: &CliClient, format: Format, cmd: ToolCmd) -> Result<(), CliError> {
    match cmd {
        ToolCmd::List => {
            let token = CliClient::op_token()?;
            let resp: Value = client
                .json("GET", "/admin/operator/tools", Auth::Operator(&token), None)
                .await?;
            print(&resp["tools"], format);
        }
    }
    Ok(())
}
