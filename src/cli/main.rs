//! `locksmith` CLI — operator and agent self-service entry point.
//!
//! Talks to the running daemon (`locksmithd`) over its admin Unix domain
//! socket. Subcommand surface matches SPEC §4.7.4.
//!
//! Exit codes (§4.7.2):
//!   0 ok | 1 generic | 2 usage | 3 auth | 4 not-found | 5 conflict

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

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
#[command(
    name = "locksmith",
    about = "Agent Locksmith CLI",
    version,
    arg_required_else_help = true
)]
struct Cli {
    /// Print JSON build identity without loading configuration or contacting a daemon.
    #[arg(long)]
    build_info: bool,

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
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Offline immutable integration definitions (operator); no activation.
    Integration {
        #[command(subcommand)]
        cmd: commands::integration::IntegrationCmd,
    },
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
    /// Offline reference-only account upgrade. Stop daemon and back up first.
    MigrateBindings(commands::migrate_bindings::ArgsOffline),
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
    if cli.build_info {
        if cli.cmd.is_some() {
            Cli::command()
                .error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "--build-info cannot be combined with a command",
                )
                .exit();
        }
        println!("{}", agent_locksmith::build_info::document("locksmith"));
        return ExitCode::SUCCESS;
    }
    let cmd = cli.cmd.unwrap_or_else(|| {
        Cli::command()
            .error(
                clap::error::ErrorKind::MissingSubcommand,
                "a command is required",
            )
            .exit()
    });

    // Offline subcommands run before client construction so they work
    // without a daemon to talk to. `bootstrap-operator` is the canonical
    // example — it mints credentials locally for a fresh deploy where
    // no admin UDS / HTTPS exists yet.
    if let Cmd::BootstrapOperator(args) = cmd {
        return match bootstrap_operator::run(args) {
            Ok(()) => ExitCode::from(0),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(e.exit_code())
            }
        };
    }

    if let Cmd::MigrateBindings(args) = cmd {
        return match commands::migrate_bindings::run(args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                let code = match e {
                    agent_locksmith::binding_migration::Error::Conflict => 5,
                    agent_locksmith::binding_migration::Error::Invalid => 2,
                    _ => 1,
                };
                eprintln!("error: {e}");
                ExitCode::from(code)
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

    let res = match cmd {
        Cmd::Agent { cmd } => agent::run(&client, cli.format, cmd).await,
        Cmd::Bootstrap { cmd } => bootstrap::run(&client, cli.format, cmd).await,
        Cmd::MigrateBindings(_) => unreachable!("handled before client construction"),
        Cmd::BootstrapOperator(_) => unreachable!("handled before client construction"),
        Cmd::Integration { cmd } => commands::integration::run(&client, cli.format, cmd).await,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// About 1 in 64 public ids start with `-` (URL-safe base64), so every
    /// positional id must parse as a value, never as a flag (#98).
    #[test]
    fn public_ids_starting_with_a_dash_parse_as_values() {
        let cases: &[&[&str]] = &[
            &["locksmith", "agent", "get", "-Oabc"],
            &["locksmith", "agent", "modify", "-Oabc"],
            &["locksmith", "agent", "revoke", "-Oabc"],
            &["locksmith", "agent", "set-cert-identity", "-Oabc", "cn=x"],
            &[
                "locksmith",
                "agent",
                "set-credential",
                "-Oabc",
                "lmstudio",
                "--no-auth",
            ],
            &[
                "locksmith",
                "agent",
                "unset-credential",
                "-Oabc",
                "lmstudio",
            ],
            &["locksmith", "agent", "credentials", "list", "-Oabc"],
            &["locksmith", "bootstrap", "revoke", "-Oabc"],
            // Consent attempt ids and account revisions are URL-safe base64 too.
            &["locksmith", "oauth", "attempt-status", "linear", "-Oabc"],
            &["locksmith", "oauth", "cancel", "linear", "-Oabc"],
            &[
                "locksmith",
                "oauth",
                "disconnect",
                "linear",
                "--label",
                "work",
                "--if-match",
                "-Oabc",
            ],
        ];
        for args in cases {
            if let Err(e) = Cli::try_parse_from(*args) {
                panic!("{args:?} failed to parse: {e}");
            }
        }
    }

    #[test]
    fn oauth_attempt_ids_leading_dash_are_opaque_values() {
        for command in ["attempt-status", "cancel"] {
            for expected in ["-fixture_attempt", "--fixture_attempt"] {
                let parsed = Cli::try_parse_from([
                    "locksmith",
                    "oauth",
                    command,
                    "fixture",
                    expected,
                    "--format",
                    "json",
                ])
                .unwrap_or_else(|e| panic!("{command}: {e}"));
                let Some(Cmd::Oauth { cmd }) = parsed.cmd else {
                    panic!("expected oauth command");
                };
                let (name, attempt) = match cmd {
                    oauth::OauthCmd::AttemptStatus { name, attempt }
                        if command == "attempt-status" =>
                    {
                        (name, attempt)
                    }
                    oauth::OauthCmd::Cancel { name, attempt } if command == "cancel" => {
                        (name, attempt)
                    }
                    _ => panic!("expected requested attempt command"),
                };
                assert_eq!(name, "fixture");
                assert_eq!(attempt, expected);
                assert!(matches!(parsed.format, Format::Json));
            }
            let help = Cli::try_parse_from(["locksmith", "oauth", command, "--help"]);
            assert_eq!(
                help.err().map(|e| e.kind()),
                Some(clap::error::ErrorKind::DisplayHelp)
            );
        }
    }

    #[test]
    fn oauth_revision_leading_dash_is_an_opaque_value() {
        for command in ["refresh", "disconnect"] {
            let parsed = Cli::try_parse_from([
                "locksmith",
                "oauth",
                command,
                "fixture",
                "--if-match",
                "-M_fixture_revision",
                "--label",
                "reader",
            ]);
            assert!(parsed.is_ok(), "{command}: {:?}", parsed.err());
        }
    }

    /// Accepting a leading `-` must not swallow real flags.
    #[test]
    fn hyphen_tolerant_ids_still_honor_flags() {
        let help = Cli::try_parse_from(["locksmith", "agent", "revoke", "--help"]);
        assert_eq!(
            help.err().map(|e| e.kind()),
            Some(clap::error::ErrorKind::DisplayHelp)
        );
        let cli =
            Cli::try_parse_from(["locksmith", "agent", "revoke", "-Oabc", "--reason", "gone"])
                .expect("id then flag parses");
        let Some(Cmd::Agent {
            cmd: agent::AgentCmd::Revoke { id, reason },
        }) = cli.cmd
        else {
            panic!("expected agent revoke");
        };
        assert_eq!(id, "-Oabc");
        assert_eq!(reason.as_deref(), Some("gone"));
    }
    #[test]
    fn controlled_selection_ids_and_revision_are_opaque() {
        let parsed = Cli::try_parse_from([
            "locksmith",
            "agent",
            "select-oauth",
            "-agent",
            "-registration",
            "--label",
            "-label",
            "--if-match",
            "-revision",
            "--format",
            "json",
        ])
        .unwrap();
        let Some(Cmd::Agent {
            cmd:
                agent::AgentCmd::SelectOauth {
                    id,
                    registration,
                    label,
                    if_match,
                },
        }) = parsed.cmd
        else {
            panic!("selection command")
        };
        assert_eq!(
            (
                id.as_str(),
                registration.as_str(),
                label.as_str(),
                if_match.as_str()
            ),
            ("-agent", "-registration", "-label", "-revision")
        );
        assert!(matches!(parsed.format, Format::Json));
    }
}
