//! Graceful shutdown coordinator (T1.10 / INF-1).
//!
//! M0 handled only SIGINT via `tokio::signal::ctrl_c`. v2 also handles
//! SIGTERM (the signal systemd delivers on `systemctl stop`) and waits up
//! to a configurable drain window for in-flight requests to complete
//! before exiting. Streaming proxy responses (R-F12 / R-N6) can take many
//! minutes; the drain window default of 30s is the maximum the operator
//! is willing to wait — long-running streams that don't complete in time
//! are forcibly closed when the listener tasks are dropped.
//!
//! For test ergonomics the coordinator also exposes `trigger()` so tests
//! can simulate signal delivery without actually sending a signal.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{info, warn};

/// Default drain window if the operator does not configure one.
pub const DEFAULT_DRAIN_WINDOW_SECS: u64 = 30;

#[derive(Clone)]
pub struct ShutdownCoordinator {
    notify: Arc<Notify>,
    drain_window: Duration,
}

impl ShutdownCoordinator {
    /// Construct without installing OS signal handlers. Useful for tests
    /// that drive shutdown via `trigger()`.
    pub fn new(drain_window: Duration) -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            drain_window,
        }
    }

    /// Construct and spawn a task that awaits SIGINT or SIGTERM and then
    /// fires the shutdown signal. Returns the coordinator for use in
    /// shutdown_signal()/drain_or_timeout().
    pub fn install(drain_window: Duration) -> Self {
        let coord = Self::new(drain_window);
        let notify = Arc::clone(&coord.notify);
        tokio::spawn(async move {
            wait_for_signal().await;
            info!("Shutdown signal received; draining listeners");
            notify.notify_waiters();
        });
        coord
    }

    /// Returns a future that resolves when shutdown is requested. Suitable
    /// for `axum::serve(...).with_graceful_shutdown(coordinator.shutdown_signal())`.
    /// Each call returns an independent future; multiple listeners can each
    /// await their own shutdown signal.
    pub fn shutdown_signal(&self) -> impl std::future::Future<Output = ()> + use<> {
        let notify = Arc::clone(&self.notify);
        async move {
            notify.notified().await;
        }
    }

    /// Trigger shutdown manually. Used by tests; in production this is
    /// driven by the OS signal handler installed by `install()`.
    pub fn trigger(&self) {
        self.notify.notify_waiters();
    }

    /// Await `task` for at most `drain_window`. On timeout, log a warning
    /// and return `Err(DrainTimeout)` — the caller is expected to drop the
    /// task and exit.
    pub async fn drain_or_timeout<F>(&self, task: F) -> Result<F::Output, DrainTimeout>
    where
        F: std::future::Future,
    {
        match tokio::time::timeout(self.drain_window, task).await {
            Ok(out) => Ok(out),
            Err(_) => {
                warn!(
                    drain_window_secs = self.drain_window.as_secs(),
                    "drain window exceeded; forcing shutdown"
                );
                Err(DrainTimeout)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DrainTimeout;

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to install SIGTERM handler; falling back to ctrl-c only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to install SIGINT handler; falling back to ctrl-c only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM"),
        _ = sigint.recv() => info!("received SIGINT"),
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("received Ctrl-C");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::sleep;

    #[tokio::test]
    async fn trigger_fires_shutdown_signal() {
        let coord = ShutdownCoordinator::new(Duration::from_secs(5));
        let signal = coord.shutdown_signal();
        let coord_clone = coord.clone();
        let trigger_task = tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            coord_clone.trigger();
        });
        signal.await;
        trigger_task.await.unwrap();
    }

    #[tokio::test]
    async fn drain_completes_within_window() {
        let coord = ShutdownCoordinator::new(Duration::from_secs(2));
        let task = async {
            sleep(Duration::from_millis(30)).await;
            42
        };
        let result = coord
            .drain_or_timeout(task)
            .await
            .expect("completes in time");
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn drain_window_timeout_returns_err() {
        let coord = ShutdownCoordinator::new(Duration::from_millis(50));
        let timed_out = AtomicBool::new(false);
        let task = async {
            sleep(Duration::from_millis(500)).await;
        };
        if coord.drain_or_timeout(task).await.is_err() {
            timed_out.store(true, Ordering::SeqCst);
        }
        assert!(timed_out.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn multiple_listeners_each_receive_signal() {
        // Each call to shutdown_signal() returns an independent future;
        // a single trigger() must wake all current waiters.
        let coord = ShutdownCoordinator::new(Duration::from_secs(5));
        let s1 = coord.shutdown_signal();
        let s2 = coord.shutdown_signal();
        let s3 = coord.shutdown_signal();
        let coord_clone = coord.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            coord_clone.trigger();
        });
        let (a, b, c) = tokio::join!(s1, s2, s3);
        let _ = (a, b, c);
    }
}
