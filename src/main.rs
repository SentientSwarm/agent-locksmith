use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;
use tracing::error;

use agent_locksmith::{config, daemon, shutdown::ShutdownCoordinator, telemetry};

#[derive(Parser)]
#[command(name = "locksmithd", about = "Agent Locksmith daemon")]
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

    let drain_window = Duration::from_secs(loaded.shutdown.drain_window_seconds);
    let coord = ShutdownCoordinator::install(drain_window);

    if let Err(e) = daemon::run(loaded, coord).await {
        error!(error = %e, "daemon exited with error");
        std::process::exit(1);
    }
}
