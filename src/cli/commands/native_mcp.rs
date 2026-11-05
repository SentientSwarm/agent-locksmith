use super::integration::request;
use crate::{
    client::{CliClient, CliError},
    output::Format,
};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::{io::Read, path::PathBuf};

#[derive(Args)]
pub struct Selection {
    /// Manual native connection name.
    connection: String,
    /// Exact agent public ID whose explicit account selection to inspect.
    #[arg(long, allow_hyphen_values = true)]
    agent: String,
}
#[derive(Args)]
pub struct Write {
    #[command(flatten)]
    selection: Selection,
    /// Strict JSON preconditions/body. Use - to read stdin.
    #[arg(long)]
    file: PathBuf,
}
#[derive(Subcommand)]
pub enum ToolCmd {
    /// Read persisted observation, freshness and source; no network request.
    Show(Selection),
    /// Initialize/list only and publish one bounded complete observation.
    Observe(Write),
    /// Record an immutable operator-reviewed contract and declared effect.
    Review(Write),
}
#[derive(Subcommand)]
pub enum GrantsCmd {
    /// Inspect finite prepared entries and their CAS revision.
    Show(Selection),
    /// Atomically replace prepared entries; an empty tools array revokes.
    Replace(Write),
}
pub async fn tool(client: &CliClient, format: Format, command: ToolCmd) -> Result<(), CliError> {
    let (selection, method, resource, body) = match command {
        ToolCmd::Show(s) => (s, "GET", "observations", None),
        ToolCmd::Observe(w) => (w.selection, "POST", "observations", Some(read(&w.file)?)),
        ToolCmd::Review(w) => (w.selection, "PUT", "reviews", Some(read(&w.file)?)),
    };
    validate(&selection)?;
    let path = format!(
        "/admin/operator/tools/{}/mcp/{resource}/{}",
        selection.connection, selection.agent
    );
    request(client, format, method, &path, body).await
}
pub async fn grants(
    client: &CliClient,
    format: Format,
    command: GrantsCmd,
) -> Result<(), CliError> {
    let (selection, method, body) = match command {
        GrantsCmd::Show(s) => (s, "GET", None),
        GrantsCmd::Replace(w) => (w.selection, "PUT", Some(read(&w.file)?)),
    };
    validate(&selection)?;
    let path = format!(
        "/admin/operator/agents/{}/mcp-grants/{}",
        selection.agent, selection.connection
    );
    request(client, format, method, &path, body).await
}
fn read(path: &std::path::Path) -> Result<Value, CliError> {
    let source: Box<dyn Read> = if path == std::path::Path::new("-") {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path)?)
    };
    let mut bytes = Vec::new();
    source.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    agent_locksmith::native_authority::api::parse(&bytes).map_err(|_| invalid())
}
fn validate(s: &Selection) -> Result<(), CliError> {
    agent_locksmith::registrations::validate_name(&s.connection).map_err(|_| invalid())?;
    if s.agent.is_empty()
        || s.agent.len() > 128
        || !s
            .agent
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}
pub async fn ingest(
    client: &CliClient,
    format: Format,
    agent: &str,
    connection: &str,
) -> Result<(), CliError> {
    validate(&Selection {
        connection: connection.into(),
        agent: agent.into(),
    })?;
    let mut bytes = Vec::new();
    std::io::stdin().take(8194).read_to_end(&mut bytes)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.len() > 8192 || !bytes.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(invalid());
    }
    let value = String::from_utf8(bytes).map_err(|_| invalid())?;
    request(
        client,
        format,
        "PUT",
        &format!("/admin/operator/agents/{agent}/credentials/{connection}/credential"),
        Some(json!({"value":value,"bearer":true})),
    )
    .await
}
fn invalid() -> CliError {
    CliError::Usage("invalid native preparation input".into())
}
