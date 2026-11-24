//! Whether the database still takes writes (AGENT-251).
//!
//! The audit promise is one row per proxied request, so a daemon whose
//! database has stopped taking writes must say so instead of serving
//! traffic it cannot record. [`WriteHealth`] is the shared flag: a failed
//! audit insert or a failed probe write sets it, and the next successful
//! write clears it. `/readyz` reports `database_unwritable` while it is set,
//! and the proxy refuses with `503 audit_unavailable` before admission, so
//! nothing reaches an upstream. [`run_probe`] rewrites one row every
//! [`PROBE_INTERVAL`], which notices a failure when no traffic arrives and
//! notices the recovery while the proxy is refusing everything.

use super::audit::AuditRepository;
use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// How often the daemon proves the database takes writes.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// How long one probe write may take before it counts as a failure. A
/// write stuck behind a hung filesystem must not keep the daemon ready.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared across every clone of the [`AuditRepository`] that owns it.
/// Starts writable, so a repository built without a probe (tests, offline
/// tools) behaves as before; the daemon probes once before it serves.
#[derive(Clone, Debug, Default)]
pub struct WriteHealth(Arc<AtomicBool>);

impl WriteHealth {
    pub fn writable(&self) -> bool {
        !self.0.load(Ordering::Acquire)
    }

    /// Record a failed write. Logs once per transition, never per
    /// request. The error is a SQLite or I/O message, which carries no
    /// bound values and so no secrets.
    pub fn failed(&self, what: &'static str, error: &dyn Display) {
        if !self.0.swap(true, Ordering::AcqRel) {
            tracing::error!(
                write = what,
                error = %error,
                "database write failed: /readyz reports database_unwritable and proxied \
                 requests are refused with 503 audit_unavailable until a write succeeds"
            );
        }
    }

    pub fn succeeded(&self) {
        if self.0.swap(false, Ordering::AcqRel) {
            tracing::info!("database writes succeed again: ready, proxying resumes");
        }
    }
}

/// Probe once, then every [`PROBE_INTERVAL`] until `shutdown` resolves.
pub async fn run_probe(
    audit: AuditRepository,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let mut ticker = tokio::time::interval(PROBE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("database write probe: shutdown signal observed; exiting cleanly");
                return;
            }
            _ = ticker.tick() => probe(&audit).await,
        }
    }
}

/// One probe write, bounded by [`PROBE_TIMEOUT`]; updates the shared
/// [`WriteHealth`].
pub async fn probe(audit: &AuditRepository) {
    match tokio::time::timeout(PROBE_TIMEOUT, audit.probe_write()).await {
        Ok(Ok(())) => audit.write_health().succeeded(),
        Ok(Err(e)) => audit.write_health().failed("probe", &e),
        Err(_) => audit
            .write_health()
            .failed("probe", &format!("timed out after {PROBE_TIMEOUT:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_writable_and_tracks_transitions() {
        let health = WriteHealth::default();
        assert!(health.writable());
        health.failed("test", &"disk I/O error");
        assert!(!health.writable());
        health.failed("test", &"disk I/O error");
        assert!(!health.writable());
        health.succeeded();
        assert!(health.writable());
    }

    #[test]
    fn clones_share_one_flag() {
        let health = WriteHealth::default();
        let other = health.clone();
        health.failed("test", &"disk I/O error");
        assert!(!other.writable());
        other.succeeded();
        assert!(health.writable());
    }
}
