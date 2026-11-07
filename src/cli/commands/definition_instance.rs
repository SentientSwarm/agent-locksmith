use super::integration::{invalid, request};
use crate::{
    client::{CliClient, CliError},
    output::Format,
};
use clap::Args;
use serde_json::json;

#[derive(Args)]
pub struct ActivationOptions {
    /// Current definition_control.revision from tool get; stale revisions never retry writes.
    #[arg(long)]
    pub if_match: String,
    /// Enable the shared compact facade as well as standard MCP.
    #[arg(long)]
    pub compact: bool,
    /// Explicit finite language for review; changing an active pin requires deactivation first.
    #[arg(long, value_parser = ["finite-v1", "finite-v2"])]
    pub contract_policy: Option<String>,
    /// Exact upstream tool name to select after a complete bounded scan (repeatable, finite-v2 only).
    #[arg(long = "selected-tool")]
    pub selected_tools: Vec<String>,
    /// Configured named or declared OAuth profile ID. Hosted Linear uses manual connections.
    #[arg(long)]
    pub oauth_profile: Option<String>,
}

pub async fn activate(
    client: &CliClient,
    format: Format,
    name: &str,
    options: ActivationOptions,
) -> Result<(), CliError> {
    let mut body = json!({"enabled":true,"compact":options.compact});
    if !options.selected_tools.is_empty() {
        body["selected_tools"] = json!(options.selected_tools);
    }
    if let Some(policy) = options.contract_policy {
        body["contract_policy"] = policy.into();
    }
    if let Some(profile) = options.oauth_profile {
        body["oauth_profile_id"] = profile.into();
    }
    transition(client, format, name, &options.if_match, body).await
}
pub async fn deactivate(
    client: &CliClient,
    format: Format,
    name: &str,
    expected: &str,
) -> Result<(), CliError> {
    transition(client, format, name, expected, json!({"enabled":false})).await
}
async fn transition(
    client: &CliClient,
    format: Format,
    name: &str,
    expected: &str,
    body: serde_json::Value,
) -> Result<(), CliError> {
    agent_locksmith::registrations::validate_name(name).map_err(invalid)?;
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("revision"));
    }
    let token = CliClient::op_token()?;
    let value: serde_json::Value = client
        .json_body_if_match(
            "PUT",
            &format!("/admin/operator/tools/{name}/definition-activation"),
            crate::client::Auth::Operator(&token),
            Some(&body),
            expected,
        )
        .await?;
    crate::output::print(&value, format);
    Ok(())
}

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
