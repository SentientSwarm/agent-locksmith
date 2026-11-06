use super::integration::{invalid, request};
use crate::{
    client::{CliClient, CliError},
    output::Format,
};
use clap::Args;
use serde_json::json;

#[derive(Args)]
pub struct Options {
    /// Exact builtin.* or local.* definition ID already imported.
    #[arg(long)]
    pub definition: String,
    #[arg(long)]
    pub revision: u32,
    /// Descriptive profile ID; does not select or store a credential.
    #[arg(long)]
    pub auth_profile: String,
    /// Native HTTPS endpoint. Creation performs no request.
    #[arg(long)]
    pub upstream: String,
    /// Allow a private destination in this disabled configuration.
    #[arg(long)]
    pub allow_private_destination: bool,
}
pub async fn run(
    client: &CliClient,
    format: Format,
    name: &str,
    options: Options,
) -> Result<(), CliError> {
    agent_locksmith::registrations::validate_name(name).map_err(invalid)?;
    agent_locksmith::definitions::validate::identity(&options.definition, options.revision)
        .map_err(invalid)?;
    let body = json!({"definition":{"id":options.definition,"revision":options.revision},"auth_profile_id":options.auth_profile,"upstream":options.upstream,"allow_private_destination":options.allow_private_destination});
    request(
        client,
        format,
        "POST",
        &format!("/admin/operator/tools/{name}/from-definition"),
        Some(body),
    )
    .await
}
