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
    /// Native connection name.
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
    /// Read persisted observation, freshness, safe readiness and source; no network.
    Show(Selection),
    /// Initialize/list only and publish one bounded complete observation.
    Observe(Write),
    /// Review an immutable contract/effect with optional fixed nonsecret context.
    Review(Write),
}
#[derive(Subcommand)]
pub enum GrantsCmd {
    /// Inspect reviewed grants, current callability and CAS revision.
    Show(Selection),
    /// Atomically replace reviewed grants; an empty tools array revokes.
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
/// Seal a value read from stdin as the agent's stored credential: a bearer,
/// or (AGENT-281) the full value of `header`, such as
/// `Authorization: Basic ...`. The value never reaches argv.
pub async fn ingest(
    client: &CliClient,
    format: Format,
    agent: &str,
    connection: &str,
    header: Option<&str>,
) -> Result<(), CliError> {
    validate(&Selection {
        connection: connection.into(),
        agent: agent.into(),
    })?;
    let mut bytes = Vec::new();
    std::io::stdin().take(8194).read_to_end(&mut bytes)?;
    let value = stdin_secret(bytes, header.is_some())?;
    let body = match header {
        Some(h) => json!({"value": value, "header": h}),
        None => json!({"value": value, "bearer": true}),
    };
    request(
        client,
        format,
        "PUT",
        &format!("/admin/operator/agents/{agent}/credentials/{connection}/credential"),
        Some(body),
    )
    .await
}
/// One trailing newline is dropped. A bearer is visible ASCII only; a
/// header value may also contain spaces (`Basic <b64>`), but not at either end.
fn stdin_secret(mut bytes: Vec<u8>, header: bool) -> Result<String, CliError> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    let allowed = |b: &u8| (0x21..=0x7e).contains(b) || (header && *b == b' ');
    let trimmed = bytes.first() != Some(&b' ') && bytes.last() != Some(&b' ');
    if bytes.is_empty() || bytes.len() > 8192 || !trimmed || !bytes.iter().all(allowed) {
        return Err(invalid());
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}
fn invalid() -> CliError {
    CliError::Usage("invalid native preparation input".into())
}

#[cfg(test)]
mod stdin_secret_tests {
    use super::stdin_secret;

    #[test]
    fn bearer_is_visible_ascii_only() {
        assert_eq!(stdin_secret(b"tok\n".to_vec(), false).unwrap(), "tok");
        assert!(stdin_secret(b"Basic abc".to_vec(), false).is_err());
        assert!(stdin_secret(b"".to_vec(), false).is_err());
    }

    #[test]
    fn header_value_may_contain_inner_spaces() {
        assert_eq!(
            stdin_secret(b"Basic abc=\n".to_vec(), true).unwrap(),
            "Basic abc="
        );
        for bad in [
            &b" Basic abc"[..],
            b"Basic abc ",
            b"Basic\tabc",
            b"a\nb",
            b"\n",
        ] {
            assert!(stdin_secret(bad.to_vec(), true).is_err(), "{bad:?}");
        }
        assert!(stdin_secret(vec![b'a'; 8193], true).is_err());
    }
}
