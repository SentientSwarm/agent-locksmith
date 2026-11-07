//! JSON logging.
//!
//! Logging starts before the config file is read ([`init_bootstrap`]) so
//! config-load warnings, such as deprecated fields, are not lost. Once the
//! config is loaded, [`Logging::apply`] sets `logging.level` (unless
//! `RUST_LOG` is set) and, when `logging.file` is set, sends every later
//! line to that file instead of stdout.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing_subscriber::{
    EnvFilter, Layer, Registry, filter::filter_fn, fmt, fmt::MakeWriter, layer::SubscriberExt,
    reload, util::SubscriberInitExt,
};

use crate::config::LoggingConfig;

type FileSlot = Arc<Mutex<Option<File>>>;

/// Handle to the installed subscriber, used to apply the loaded config.
pub struct Logging {
    filter: reload::Handle<EnvFilter, Registry>,
    file: FileSlot,
}

/// Install the JSON subscriber at `RUST_LOG` or `info`, writing to stdout.
pub fn init_bootstrap() -> Logging {
    let (filter, handle) = reload::Layer::new(env_filter("info"));
    let file: FileSlot = Arc::default();
    tracing_subscriber::registry()
        .with(filter)
        // SDK events include client metadata, request arguments and cancellation reasons.
        // Never expose them, even when RUST_LOG explicitly enables SDK tracing.
        .with(
            fmt::layer()
                .json()
                .with_target(true)
                .with_writer(Sink(file.clone()))
                .with_filter(filter_fn(|metadata| {
                    metadata.target() != "rmcp" && !metadata.target().starts_with("rmcp::")
                })),
        )
        .init();
    Logging {
        filter: handle,
        file,
    }
}

/// Install logging and apply `config` in one step.
pub fn init_logging(config: Option<&LoggingConfig>) {
    if let Err(e) = init_bootstrap().apply(config) {
        tracing::error!(error = %e, "logging.file could not be opened; logging to stdout");
    }
}

impl Logging {
    /// Apply `logging.level` and `logging.file`. Fails only when the file
    /// cannot be opened for appending.
    pub fn apply(&self, config: Option<&LoggingConfig>) -> io::Result<()> {
        let Some(config) = config else {
            return Ok(());
        };
        if std::env::var_os("RUST_LOG").is_none() {
            // Reload fails only if the subscriber is gone; nothing to log to then.
            let _ = self.filter.reload(env_filter(&config.level));
        }
        if let Some(path) = &config.file {
            let file = open_log(Path::new(path))?;
            *self.file.lock().unwrap_or_else(|p| p.into_inner()) = Some(file);
        }
        Ok(())
    }
}

fn env_filter(level: &str) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))
}

fn open_log(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o640);
    options.open(path)
}

/// Writes each formatted line to the configured file, or stdout.
#[derive(Clone)]
struct Sink(FileSlot);

impl<'a> MakeWriter<'a> for Sink {
    type Writer = Sink;
    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut slot = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match slot.as_mut() {
            Some(file) => file.write(buf),
            None => io::stdout().lock().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut slot = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match slot.as_mut() {
            Some(file) => file.flush(),
            None => io::stdout().lock().flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_writes_to_the_configured_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l.log");
        let slot: FileSlot = Arc::new(Mutex::new(Some(open_log(&path).unwrap())));
        let mut sink = Sink(slot);
        sink.write_all(b"{\"a\":1}\n").unwrap();
        sink.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"a\":1}\n");
    }

    #[test]
    fn open_log_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l.log");
        std::fs::write(&path, "old\n").unwrap();
        open_log(&path).unwrap().write_all(b"new\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old\nnew\n");
    }
}
