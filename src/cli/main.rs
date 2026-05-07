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

use commands::{
    agent, audit, bootstrap, bootstrap_operator, export, infra, model, mtls, oauth, self_svc, tool,
};
use output::Format;

/// Default admin socket location. Operators can override with --socket
/// or the LOCKSMITH_SOCKET env var. Matches the runbook default.
const DEFAULT_SOCKET: &str = "/var/run/locksmith/admin.sock";

#[derive(Parser)]
#[command(name = "locksmith", about = "Agent Locksmith CLI", version)]
struct Cli {
    /// Path to the admin UDS. Falls back to LOCKSMITH_SOCKET, then the
    /// system default. Ignored when `--admin-url` (or
    /// `LOCKSMITH_ADMIN_URL`) is set.
    #[arg(long, global = true, env = "LOCKSMITH_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    /// Admin HTTPS URL (e.g. `https://locksmith.example.com:9201`).
    /// When set, the CLI talks to the daemon over the M4 admin HTTPS
    /// listener instead of the local UDS. Falls back to
    /// `LOCKSMITH_ADMIN_URL` if the flag is omitted.
    #[arg(long, global = true, env = "LOCKSMITH_ADMIN_URL")]
    admin_url: Option<String>,

    /// Path to a PEM CA bundle used to verify the admin HTTPS endpoint.
    /// Required when the daemon presents a self-signed or private-CA
    /// certificate (smallstep, openclaw-hardened, etc.). Honored only
    /// when `--admin-url` is set.
    #[arg(long, global = true, env = "LOCKSMITH_CA_BUNDLE")]
    ca_bundle: Option<PathBuf>,

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
    /// Mint a fresh operator credential. Self-contained Rust-native
    /// flow for standalone deployments — replaces the site-side
    /// `bootstrap-operator.py`. Writes operators.yaml content to
    /// stdout; prints the wire token ONCE to stderr.
    BootstrapOperator(bootstrap_operator::BootstrapOperatorArgs),
    /// Tool management (operator).
    Tool {
        #[command(subcommand)]
        cmd: tool::ToolCmd,
    },
    /// Model management (operator). Phase E.4 (v2.0.0).
    Model {
        #[command(subcommand)]
        cmd: model::ModelCmd,
    },
    /// Infrastructure middleware management (operator-only). Phase E.4 (v2.0.0).
    Infra {
        #[command(subcommand)]
        cmd: infra::InfraCmd,
    },
    /// OAuth session management (operator). Phase F.4 (v2.0.0).
    Oauth {
        #[command(subcommand)]
        cmd: oauth::OauthCmd,
    },
    /// Audit log queries (operator).
    Audit {
        #[command(subcommand)]
        cmd: audit::AuditCmd,
    },
    /// Export operator-visible state (UC-10).
    Export {
        #[command(subcommand)]
        cmd: export::ExportCmd,
    },
    /// mTLS-related operations (M6).
    Mtls {
        #[command(subcommand)]
        cmd: mtls::MtlsCmd,
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

    // Offline subcommands run before client construction so they work
    // without a daemon to talk to. `bootstrap-operator` is the canonical
    // example — it mints credentials locally for a fresh deploy where
    // no admin UDS / HTTPS exists yet.
    if let Cmd::BootstrapOperator(args) = cli.cmd {
        return match bootstrap_operator::run(args) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(e.exit_code())
            }
        };
    }

    let client = match client::CliClient::from_options(
        &cli.socket,
        cli.admin_url.as_deref(),
        cli.ca_bundle.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(e.exit_code());
        }
    };

    let res = match cli.cmd {
        Cmd::Agent { cmd } => agent::run(&client, cli.format, cmd).await,
        Cmd::Bootstrap { cmd } => bootstrap::run(&client, cli.format, cmd).await,
        Cmd::BootstrapOperator(_) => unreachable!("handled before client construction"),
        Cmd::Tool { cmd } => tool::run(&client, cli.format, cmd).await,
        Cmd::Model { cmd } => model::run(&client, cli.format, cmd).await,
        Cmd::Infra { cmd } => infra::run(&client, cli.format, cmd).await,
        Cmd::Oauth { cmd } => oauth::run(&client, cli.format, cmd).await,
        Cmd::Audit { cmd } => audit::run(&client, cli.format, cmd).await,
        Cmd::Export { cmd } => export::run(&client, cli.format, cmd).await,
        Cmd::Mtls { cmd } => mtls::run(cli.format, cmd).await,
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
