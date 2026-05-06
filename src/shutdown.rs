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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{info, warn};

/// Default drain window if the operator does not configure one.
pub const DEFAULT_DRAIN_WINDOW_SECS: u64 = 30;

#[derive(Clone)]
pub struct ShutdownCoordinator {
    /// Wake currently-waiting `shutdown_signal()` futures.
    notify: Arc<Notify>,
    /// Latched signal state. Set by `trigger()` (and the OS signal handler
    /// installed by `install()`); checked by `shutdown_signal()` so a
    /// future created AFTER trigger fires resolves immediately rather
    /// than waiting forever for a notification that's already been
    /// dispatched. Without this latch, `Notify::notify_waiters` only
    /// wakes futures already registered, making `await` order safety-
    /// critical for any caller — see `await_shutdown_then_drain`.
    triggered: Arc<AtomicBool>,
    drain_window: Duration,
}

impl ShutdownCoordinator {
    /// Construct without installing OS signal handlers. Useful for tests
    /// that drive shutdown via `trigger()`.
    pub fn new(drain_window: Duration) -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            triggered: Arc::new(AtomicBool::new(false)),
            drain_window,
        }
    }

    /// Construct and spawn a task that awaits SIGINT or SIGTERM and then
    /// fires the shutdown signal. Returns the coordinator for use in
    /// shutdown_signal() / await_shutdown_then_drain().
    pub fn install(drain_window: Duration) -> Self {
        let coord = Self::new(drain_window);
        let notify = Arc::clone(&coord.notify);
        let triggered = Arc::clone(&coord.triggered);
        tokio::spawn(async move {
            wait_for_signal().await;
            info!("Shutdown signal received; draining listeners");
            triggered.store(true, Ordering::SeqCst);
            notify.notify_waiters();
        });
        coord
    }

    /// Returns a future that resolves when shutdown is requested.
    /// Suitable for
    /// `axum::serve(...).with_graceful_shutdown(coordinator.shutdown_signal())`.
    /// Each call returns an independent future; multiple listeners can
    /// each await their own shutdown signal. Resolves immediately if
    /// `trigger()` has already fired (latched via `triggered`), so
    /// callers don't have to worry about subscribing before the signal.
    pub fn shutdown_signal(&self) -> impl std::future::Future<Output = ()> + use<> {
        let notify = Arc::clone(&self.notify);
        let triggered = Arc::clone(&self.triggered);
        async move {
            if triggered.load(Ordering::SeqCst) {
                return;
            }
            // Re-check under Notify's wake-on-load semantics: register
            // for a notification first, then re-check the flag to close
            // the trigger-after-load-but-before-await race.
            let notified = notify.notified();
            tokio::pin!(notified);
            if triggered.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    /// Trigger shutdown manually. Used by tests; in production this is
    /// driven by the OS signal handler installed by `install()`.
    pub fn trigger(&self) {
        self.triggered.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// True if `trigger()` (or the installed signal handler) has fired.
    pub fn is_triggered(&self) -> bool {
        self.triggered.load(Ordering::SeqCst)
    }

    /// Await `task` for at most `drain_window`. On timeout, log a warning
    /// and return `Err(DrainTimeout)` — the caller is expected to drop the
    /// task and exit.
    ///
    /// The drain window starts ticking when this method is called.
    /// **Use `await_shutdown_then_drain` instead** for the daemon's
    /// top-level drain — it waits for the shutdown signal first so the
    /// drain window measures only the post-signal grace period, not the
    /// daemon's entire serving lifetime.
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

    /// Await the shutdown signal, then await `task` for at most
    /// `drain_window`. This is the correct top-level shape for
    /// daemon::run: the listener tasks themselves only complete once
    /// the shutdown signal fires (they hold their own
    /// `shutdown_signal()` futures wired into axum's
    /// `with_graceful_shutdown`), and the drain window is the bounded
    /// grace period in which we wait for in-flight requests to finish
    /// after the signal arrives — NOT the daemon's entire serving
    /// lifetime.
    ///
    /// Pre-fix bug (M9 / B1 follow-up): daemon::run called
    /// `drain_or_timeout(drain)` directly, which started the timer at
    /// daemon-startup. With no SIGTERM during that window, the timer
    /// fired and the daemon force-exited. Long-running streaming LLM
    /// responses that took longer than `drain_window_seconds` were
    /// killed mid-stream.
    pub async fn await_shutdown_then_drain<F>(&self, task: F) -> Result<F::Output, DrainTimeout>
    where
        F: std::future::Future,
    {
        self.shutdown_signal().await;
        info!("Shutdown signal observed by drain coordinator");
        self.drain_or_timeout(task).await
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

    // Regression for the shutdown-latch bug: a `shutdown_signal()`
    // future created AFTER `trigger()` has fired must resolve
    // immediately rather than waiting forever for a notification that's
    // already been dispatched. Pre-fix, `Notify::notify_waiters` only
    // woke currently-registered futures.
    #[tokio::test]
    async fn shutdown_signal_after_trigger_resolves_immediately() {
        let coord = ShutdownCoordinator::new(Duration::from_secs(5));
        coord.trigger();
        // Subscribing AFTER the trigger must NOT block.
        let result =
            tokio::time::timeout(Duration::from_millis(100), coord.shutdown_signal()).await;
        assert!(
            result.is_ok(),
            "shutdown_signal() must resolve immediately when trigger has already fired"
        );
        assert!(coord.is_triggered());
    }

    // Regression for the M9-exposed daemon bug: with no shutdown signal,
    // the drain timer must NOT start counting. The daemon must stay up
    // indefinitely until a real signal arrives. Pre-fix, the daemon
    // force-exited drain_window seconds after startup regardless of
    // whether a signal had fired.
    #[tokio::test]
    async fn await_shutdown_then_drain_does_not_time_out_without_signal() {
        let coord = ShutdownCoordinator::new(Duration::from_millis(50));
        // The "task" is a future that completes only when shutdown is
        // signalled — same shape as the real daemon's `drain` (a
        // tokio::join! over listener tasks each holding a
        // shutdown_signal future).
        let drain = coord.shutdown_signal();
        // Race the daemon-shape drain against a 200ms wall clock that's
        // 4× the drain_window. Pre-fix this would resolve as Ok(Err(_))
        // after 50ms because drain_or_timeout's timer started immediately.
        let race = tokio::time::timeout(
            Duration::from_millis(200),
            coord.await_shutdown_then_drain(drain),
        )
        .await;
        assert!(
            race.is_err(),
            "await_shutdown_then_drain must not return until shutdown is signalled (got: {race:?})"
        );
    }

    // Once shutdown IS signalled, the drain window applies to the
    // post-signal grace period — same semantics as before, just gated
    // on the signal.
    #[tokio::test]
    async fn await_shutdown_then_drain_applies_window_after_signal() {
        let coord = ShutdownCoordinator::new(Duration::from_millis(50));
        let coord_clone = coord.clone();
        // Trigger after 30ms; then a 500ms task must time out (50ms
        // drain window) → DrainTimeout.
        tokio::spawn(async move {
            sleep(Duration::from_millis(30)).await;
            coord_clone.trigger();
        });
        let task = sleep(Duration::from_millis(500));
        let result = coord.await_shutdown_then_drain(task).await;
        assert!(
            result.is_err(),
            "task longer than drain_window must DrainTimeout AFTER signal"
        );
    }
}
