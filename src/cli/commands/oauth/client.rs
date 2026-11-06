use super::*;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum ClientCmd {
    /// Seal one immutable owner/profile/client generation; plaintext is stdin only.
    Set {
        name: String,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        client_generation: u64,
        #[arg(long, required = true)]
        secret_stdin: bool,
    },
    /// Read reveal-never metadata for an owned generation.
    Status {
        name: String,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        client_generation: u64,
    },
    /// Permanently retire an owned generation; replacement requires a new generation.
    Retire {
        name: String,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        client_generation: u64,
    },
}

pub async fn run(client: &CliClient, format: Format, cmd: ClientCmd) -> Result<(), CliError> {
    match cmd {
        ClientCmd::Set {
            name,
            profile,
            client_generation,
            secret_stdin: _,
        } => set(client, format, &name, &profile, client_generation).await,
        ClientCmd::Status {
            name,
            profile,
            client_generation,
        } => metadata(client, format, &name, &profile, client_generation, "GET").await,
        ClientCmd::Retire {
            name,
            profile,
            client_generation,
        } => metadata(client, format, &name, &profile, client_generation, "DELETE").await,
    }
}

async fn set(
    client: &CliClient,
    format: Format,
    name: &str,
    profile: &str,
    generation: u64,
) -> Result<(), CliError> {
    component(name)?;
    component(profile)?;
    let secret = read_secret()?;
    let op = CliClient::op_token()?;
    let body = json!({"profile":profile,"client_generation":generation,"secret":secret});
    let result: Value = client
        .json(
            "POST",
            &format!("/admin/operator/tools/{name}/oauth/client"),
            Auth::Operator(&op),
            Some(&body),
        )
        .await?;
    print(&result, format);
    Ok(())
}

async fn metadata(
    client: &CliClient,
    format: Format,
    name: &str,
    profile: &str,
    generation: u64,
    method: &str,
) -> Result<(), CliError> {
    component(name)?;
    component(profile)?;
    let op = CliClient::op_token()?;
    let result: Value = client
        .json(
            method,
            &format!("/admin/operator/tools/{name}/oauth/clients/{profile}/{generation}"),
            Auth::Operator(&op),
            None,
        )
        .await?;
    print(&result, format);
    Ok(())
}

fn read_secret() -> Result<String, CliError> {
    use std::io::Read;
    let mut value = String::new();
    std::io::stdin()
        .take(8194)
        .read_to_string(&mut value)
        .map_err(|_| CliError::Usage("read client secret stdin".into()))?;
    let secret = value.strip_suffix('\n').unwrap_or(&value);
    if secret.is_empty()
        || secret.len() > 8192
        || !secret.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(CliError::Usage("invalid client secret input".into()));
    }
    Ok(secret.to_owned())
}
