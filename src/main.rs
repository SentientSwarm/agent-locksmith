use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::info;

use agent_locksmith::{app, config, shutdown::ShutdownCoordinator, telemetry};

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
        eprintln!("Failed to load config from {}: {}", cli.config.display(), e);
        std::process::exit(1);
    });

    telemetry::init_logging(loaded.logging.as_ref());

    let addr = SocketAddr::new(
        loaded.listen.host.parse().unwrap_or([127, 0, 0, 1].into()),
        loaded.listen.port,
    );

    let tool_count = loaded.active_tools().len();
    let drain_window = Duration::from_secs(loaded.shutdown.drain_window_seconds);

    info!(
        listen = %addr,
        tools = tool_count,
        drain_window_secs = drain_window.as_secs(),
        "Starting agent-locksmith"
    );

    let router = app::build_app(loaded);

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        eprintln!("Failed to bind to {addr}: {e}");
        std::process::exit(1);
    });

    info!("Listening on {addr}");

    // Install SIGINT + SIGTERM handlers; the server's graceful_shutdown
    // future resolves when either is received (or when trigger() is
    // called from a test). The drain window bounds how long we wait for
    // in-flight requests to complete after the signal — INF-1.
    let coordinator = ShutdownCoordinator::install(drain_window);
    let server =
        axum::serve(listener, router).with_graceful_shutdown(coordinator.shutdown_signal());

    match coordinator.drain_or_timeout(server.into_future()).await {
        Ok(Ok(())) => info!("clean shutdown complete"),
        Ok(Err(e)) => {
            eprintln!("server error: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            // drain window exceeded; the server task is dropped on scope
            // exit. Listeners closing will terminate any remaining
            // connections.
            std::process::exit(0);
        }
    }
}
