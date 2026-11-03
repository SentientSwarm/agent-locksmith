use tracing_subscriber::{
    EnvFilter, Layer, filter::filter_fn, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

use crate::config::LoggingConfig;

pub fn init_logging(config: Option<&LoggingConfig>) {
    let level = config.map(|c| c.level.as_str()).unwrap_or("info");

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        // SDK events include client metadata, request arguments and cancellation reasons.
        // Never expose them, even when RUST_LOG explicitly enables SDK tracing.
        .with(
            fmt::layer()
                .json()
                .with_target(true)
                .with_filter(filter_fn(|metadata| {
                    metadata.target() != "rmcp" && !metadata.target().starts_with("rmcp::")
                })),
        )
        .init();
}
