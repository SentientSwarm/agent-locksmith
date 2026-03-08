use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tracing::info;

use agent_locksmith::{app, config, telemetry};

#[derive(Parser)]
#[command(name = "locksmith", about = "Agent Locksmith")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/locksmith/config.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let loaded = config::load_config(&cli.config).unwrap_or_else(|e| {
        eprintln!(
            "Failed to load config from {}: {}",
            cli.config.display(),
            e
        );
        std::process::exit(1);
    });

    telemetry::init_logging(loaded.logging.as_ref());

    let addr = SocketAddr::new(
        loaded
            .listen
            .host
            .parse()
            .unwrap_or([127, 0, 0, 1].into()),
        loaded.listen.port,
    );

    let tool_count = loaded.active_tools().len();

    info!(
        listen = %addr,
        tools = tool_count,
        "Starting agent-locksmith"
    );

    let router = app::build_app(loaded);

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        eprintln!("Failed to bind to {}: {}", addr, e);
        std::process::exit(1);
    });

    info!("Listening on {}", addr);

    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to register ctrl-c handler");
        info!("Shutting down");
    };

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .unwrap();
}
