//! Offline definitions use the same authenticated backend as all operators.
use crate::{
    client::{Auth, CliClient, CliError},
    output::{Format, print},
};
use agent_locksmith::definitions;
use clap::Subcommand;
use serde_json::Value;
use std::{
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Subcommand)]
pub enum IntegrationCmd {
    /// Import one strict immutable definition; grants nothing and contacts no provider.
    Import {
        #[arg(long)]
        file: PathBuf,
    },
    /// Read an exact saved revision. No latest alias or live verification.
    Get {
        id: String,
        #[arg(long)]
        revision: u32,
    },
}
pub async fn run(
    client: &CliClient,
    format: Format,
    command: IntegrationCmd,
) -> Result<(), CliError> {
    match command {
        IntegrationCmd::Import { file } => {
            let definition = read(&file)?;
            let path = path(&definition.id, definition.revision)?;
            request(
                client,
                format,
                "PUT",
                &path,
                Some(serde_json::to_value(definition)?),
            )
            .await
        }
        IntegrationCmd::Get { id, revision } => {
            request(client, format, "GET", &path(&id, revision)?, None).await
        }
    }
}
fn read(path: &Path) -> Result<definitions::Definition, CliError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(definitions::MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    definitions::parse(&bytes).map_err(invalid)
}
fn path(id: &str, revision: u32) -> Result<String, CliError> {
    definitions::validate::identity(id, revision).map_err(invalid)?;
    Ok(format!(
        "/admin/operator/integration-definitions/{id}/revisions/{revision}"
    ))
}
pub(super) async fn request(
    client: &CliClient,
    format: Format,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<(), CliError> {
    let token = CliClient::op_token()?;
    let response: Value = client
        .json(method, path, Auth::Operator(&token), body.as_ref())
        .await?;
    print(&response, format);
    Ok(())
}
pub(super) fn invalid(_: impl std::fmt::Display) -> CliError {
    CliError::Usage("invalid or unsupported integration definition input".into())
}
