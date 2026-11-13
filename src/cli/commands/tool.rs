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
    /// Deliberately activate an eligible local definition; no account, ACL or tool grant is created.
    ActivateDefinition {
        name: String,
        #[command(flatten)]
        options: super::definition_instance::ActivationOptions,
    },
    /// Disable a promoted definition and retire all connection authority; sealed accounts remain.
    DeactivateDefinition {
        name: String,
        #[arg(long)]
        if_match: String,
    },
    /// Observe/review native tools; deliberate per-agent grants enable supported calls.
    Mcp {
        #[command(subcommand)]
        command: super::native_mcp::ToolCmd,
    },
    /// Create a disabled, immutable instance of an exact definition; no accounts or grants.
    FromDefinition {
        name: String,
        #[command(flatten)]
        options: super::definition_instance::Options,
    },
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
        opts: Box<PutOpts>,
    },
    /// Seal the route's own key (a broker key) read from stdin.
    SetKey {
        /// Registration name.
        name: String,
        /// Send the key in this header instead of `Authorization: Bearer`.
        #[arg(long)]
        header: Option<String>,
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
        ToolCmd::ActivateDefinition { name, options } => {
            super::definition_instance::activate(client, format, &name, options).await
        }
        ToolCmd::DeactivateDefinition { name, if_match } => {
            super::definition_instance::deactivate(client, format, &name, &if_match).await
        }
        ToolCmd::Mcp { command } => super::native_mcp::tool(client, format, command).await,
        ToolCmd::FromDefinition { name, options } => {
            super::definition_instance::run(client, format, &name, options).await
        }
        ToolCmd::List => registration::do_list(client, format, CliKind::Tool).await,
        ToolCmd::Get { name } => registration::do_get(client, format, CliKind::Tool, &name).await,
        ToolCmd::SetKey { name, header } => {
            registration::do_set_key(client, format, CliKind::Tool, &name, header).await
        }
        ToolCmd::Put { name, opts } => {
            registration::do_put(client, format, CliKind::Tool, &name, *opts).await
        }
        ToolCmd::Delete { name } => {
            registration::do_delete(client, format, CliKind::Tool, &name).await
        }
        ToolCmd::Enable { name } => {
            registration::do_enable(client, format, CliKind::Tool, &name).await
        }
    }
}
