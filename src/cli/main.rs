//! `locksmith` CLI — operator and agent self-service entry point.
//!
//! Talks to the running daemon (`locksmithd`) over its admin Unix domain
//! socket. Subcommand surface matches SPEC §4.7.4.
//!
//! Exit codes (§4.7.2):
//!   0 ok | 1 generic | 2 usage | 3 auth | 4 not-found | 5 conflict

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod client;
mod commands;
mod output;

use commands::{agent, bootstrap, self_svc, tool};
use output::Format;

/// Default admin socket location. Operators can override with --socket
/// or the LOCKSMITH_SOCKET env var. Matches the runbook default.
const DEFAULT_SOCKET: &str = "/var/run/locksmith/admin.sock";

#[derive(Parser)]
#[command(name = "locksmith", about = "Agent Locksmith CLI", version)]
struct Cli {
    /// Path to the admin UDS. Falls back to LOCKSMITH_SOCKET, then the
    /// system default.
    #[arg(long, global = true, env = "LOCKSMITH_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    /// Output format (where applicable).
    #[arg(long, global = true, value_enum, default_value_t = Format::Table)]
    format: Format,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Agent management (operator).
    Agent {
        #[command(subcommand)]
        cmd: agent::AgentCmd,
    },
    /// Bootstrap-token management (operator).
    Bootstrap {
        #[command(subcommand)]
        cmd: bootstrap::BootstrapCmd,
    },
    /// Tool management (operator).
    Tool {
        #[command(subcommand)]
        cmd: tool::ToolCmd,
    },
    /// Self-service: show your agent status.
    Status,
    /// Self-service: rotate your agent token.
    Rotate {
        /// Current agent secret. Defaults to the secret part of
        /// LOCKSMITH_AGENT_TOKEN (i.e. the part after `.`).
        #[arg(long)]
        current_secret: Option<String>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let client = client::CliClient::new(&cli.socket);

    let res = match cli.cmd {
        Cmd::Agent { cmd } => agent::run(&client, cli.format, cmd).await,
        Cmd::Bootstrap { cmd } => bootstrap::run(&client, cli.format, cmd).await,
        Cmd::Tool { cmd } => tool::run(&client, cli.format, cmd).await,
        Cmd::Status => self_svc::status(&client, cli.format).await,
        Cmd::Rotate { current_secret } => {
            self_svc::rotate(&client, cli.format, current_secret).await
        }
    };

    match res {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
