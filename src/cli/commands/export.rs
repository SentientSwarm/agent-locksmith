//! `locksmith export ...` operator subcommands. UC-10. Excludes
//! secret material per R-F14.

use clap::Subcommand;
use serde_json::Value;

use crate::client::{Auth, CliClient, CliError};
use crate::output::Format;

#[derive(Subcommand)]
pub enum ExportCmd {
    /// Export all agents as a structured snapshot.
    Agents,
}

pub async fn run(client: &CliClient, format: Format, cmd: ExportCmd) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    match cmd {
        ExportCmd::Agents => {
            let resp: Value = client
                .json(
                    "GET",
                    "/admin/operator/agents?include_revoked=true",
                    Auth::Operator(&token),
                    None,
                )
                .await?;
            let agents = resp["agents"].clone();
            // The /admin/operator/agents response already excludes
            // secret_hash and the cleartext token; nothing further to
            // strip. Emit in the chosen format directly so the dump is
            // operator-readable + replayable.
            match format {
                Format::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&agents).expect("json serializes")
                ),
                Format::Yaml | Format::Table => {
                    // Tables don't make sense for an export bundle —
                    // tables are interactive output, exports are
                    // structured artifacts. Default to YAML.
                    println!(
                        "{}",
                        serde_yaml::to_string(&agents).expect("yaml serializes")
                    );
                }
            }
        }
    }
    Ok(())
}
