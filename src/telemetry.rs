use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::LoggingConfig;

pub fn init_logging(config: Option<&LoggingConfig>) {
    let level = config.map(|c| c.level.as_str()).unwrap_or("info");

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json().with_target(true))
        .init();
}
