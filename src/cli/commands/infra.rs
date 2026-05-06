//! `locksmith infra ...` subcommands. Phase E.4 (v2.0.0).
//!
//! Operator-only — kind=infra registrations are middleware the proxy
//! itself calls. NOT agent-callable; no agent-facing discovery endpoint.
//!
//! Symmetric to [`crate::commands::tool`] and [`crate::commands::model`]
//! at the CLI level. All dispatch goes through
//! [`crate::commands::registration`].

use clap::Subcommand;

use crate::client::{CliClient, CliError};
use crate::commands::registration::{self, CliKind, PutOpts};
use crate::output::Format;

#[derive(Subcommand)]
pub enum InfraCmd {
    /// List configured infra registrations.
    List,
    /// Show one infra registration by name.
    Get {
        /// Registration name.
        name: String,
    },
    /// Register or update an infra middleware. `--auth` may be omitted
    /// (defaults to `none` server-side).
    Put {
        /// Registration name.
        name: String,
        #[command(flatten)]
        opts: PutOpts,
    },
    /// Delete an infra registration.
    Delete {
        /// Registration name.
        name: String,
    },
    /// Re-enable a previously-disabled infra registration.
    Enable {
        /// Registration name.
        name: String,
    },
}

pub async fn run(client: &CliClient, format: Format, cmd: InfraCmd) -> Result<(), CliError> {
    match cmd {
        InfraCmd::List => registration::do_list(client, format, CliKind::Infra).await,
        InfraCmd::Get { name } => registration::do_get(client, format, CliKind::Infra, &name).await,
        InfraCmd::Put { name, opts } => {
            registration::do_put(client, format, CliKind::Infra, &name, opts).await
        }
        InfraCmd::Delete { name } => {
            registration::do_delete(client, format, CliKind::Infra, &name).await
        }
        InfraCmd::Enable { name } => {
            registration::do_enable(client, format, CliKind::Infra, &name).await
        }
    }
}
