//! `locksmith model ...` subcommands. Phase E.4 (v2.0.0).
//!
//! Symmetric to [`crate::commands::tool`] — same surface, kind=model.
//! All dispatch goes through [`crate::commands::registration`].

use clap::Subcommand;

use crate::client::{CliClient, CliError};
use crate::commands::registration::{self, CliKind, PutOpts};
use crate::output::Format;

#[derive(Subcommand)]
pub enum ModelCmd {
    /// List configured models.
    List,
    /// Show one model by name.
    Get {
        /// Registration name.
        name: String,
    },
    /// Register or update a model. `--auth` is required and must be non-`none`.
    Put {
        /// Registration name.
        name: String,
        #[command(flatten)]
        opts: PutOpts,
    },
    /// Delete a model.
    Delete {
        /// Registration name.
        name: String,
    },
    /// Re-enable a previously-disabled model.
    Enable {
        /// Registration name.
        name: String,
    },
}

pub async fn run(client: &CliClient, format: Format, cmd: ModelCmd) -> Result<(), CliError> {
    match cmd {
        ModelCmd::List => registration::do_list(client, format, CliKind::Model).await,
        ModelCmd::Get { name } => registration::do_get(client, format, CliKind::Model, &name).await,
        ModelCmd::Put { name, opts } => {
            registration::do_put(client, format, CliKind::Model, &name, opts).await
        }
        ModelCmd::Delete { name } => {
            registration::do_delete(client, format, CliKind::Model, &name).await
        }
        ModelCmd::Enable { name } => {
            registration::do_enable(client, format, CliKind::Model, &name).await
        }
    }
}
