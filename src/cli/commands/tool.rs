//! `locksmith tool ...` subcommands.
//!
//! Phase E.4 (v2.0.0): expanded from the M9-era `list` to the full
//! list/get/put/delete/enable surface backed by the `registrations`
//! table and the `/admin/operator/tools/...` endpoints. All five
//! subcommands share dispatch via [`crate::commands::registration`].

use clap::Subcommand;

use crate::client::{CliClient, CliError};
use crate::commands::registration::{self, CliKind, PutOpts};
use crate::output::Format;

#[derive(Subcommand)]
pub enum ToolCmd {
    /// List configured tools (kind=tool registrations, including disabled).
    List,
    /// Show one tool by name.
    Get {
        /// Registration name.
        name: String,
    },
    /// Register or update a tool. `--auth` is required (use `none` for authless).
    Put {
        /// Registration name.
        name: String,
        #[command(flatten)]
        opts: PutOpts,
    },
    /// Delete a tool. Operator rows are removed; seed rows are flipped to disabled=1.
    Delete {
        /// Registration name.
        name: String,
    },
    /// Re-enable a previously-disabled tool (seed or operator).
    Enable {
        /// Registration name.
        name: String,
    },
}

pub async fn run(client: &CliClient, format: Format, cmd: ToolCmd) -> Result<(), CliError> {
    match cmd {
        ToolCmd::List => registration::do_list(client, format, CliKind::Tool).await,
        ToolCmd::Get { name } => registration::do_get(client, format, CliKind::Tool, &name).await,
        ToolCmd::Put { name, opts } => {
            registration::do_put(client, format, CliKind::Tool, &name, opts).await
        }
        ToolCmd::Delete { name } => {
            registration::do_delete(client, format, CliKind::Tool, &name).await
        }
        ToolCmd::Enable { name } => {
            registration::do_enable(client, format, CliKind::Tool, &name).await
        }
    }
}
