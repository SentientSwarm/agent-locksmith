//! Whether the database still takes writes (AGENT-251).
//!
//! The audit promise is one row per proxied request, so a daemon whose
//! database has stopped taking writes must say so instead of serving
//! traffic it cannot record. [`WriteHealth`] is the shared flag: a failed
//! audit insert or a failed probe write sets it, and a successful write that
//! began after the latest failure clears it. A write that began earlier may
//! have committed just before the file failed, so its success proves nothing
//! about the database now. `/readyz` reports `database_unwritable` while it
//! is set, and the proxy refuses with `503 audit_unavailable` before
//! admission, so nothing reaches an upstream. [`run_probe`] rewrites one row
//! every [`PROBE_INTERVAL`], which notices a failure when no traffic arrives and
//! notices the recovery while the proxy is refusing everything.

use super::audit::AuditRepository;
use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
pub struct WriteHealth(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    /// One counter orders write attempts and recorded failures.
    tickets: AtomicU64,
    /// The ticket of the latest recorded failure; 0 while writable.
    failed_at: AtomicU64,
}

/// Taken by [`WriteHealth::begin`] before a write starts.
#[derive(Clone, Copy, Debug)]
pub struct Attempt(u64);

impl WriteHealth {
    pub fn writable(&self) -> bool {
        self.0.failed_at.load(Ordering::Acquire) == 0
    }

    /// Take a ticket before starting a write; report its outcome with it.
    pub fn begin(&self) -> Attempt {
        Attempt(self.ticket())
    }

    fn ticket(&self) -> u64 {
        self.0.tickets.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Record a failed write. Logs once per transition, never per
    /// request. The error is a SQLite or I/O message, which carries no
    /// bound values and so no secrets.
    pub fn failed(&self, what: &'static str, error: &dyn Display) {
        let at = self.ticket();
        if self.0.failed_at.fetch_max(at, Ordering::AcqRel) == 0 {
            tracing::error!(
                write = what,
                error = %error,
                "database write failed: /readyz reports database_unwritable and proxied \
                 requests are refused with 503 audit_unavailable until a write succeeds"
            );
        }
    }

    /// Record a successful write. It clears the flag only if the write began
    /// after the latest recorded failure.
    pub fn succeeded(&self, attempt: Attempt) {
        let mut failed_at = self.0.failed_at.load(Ordering::Acquire);
        while failed_at != 0 && attempt.0 > failed_at {
            match self.0.failed_at.compare_exchange(
                failed_at,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    tracing::info!("database writes succeed again: ready, proxying resumes");
                    return;
                }
                Err(current) => failed_at = current,
            }
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
///
/// While writable, the probe rewrites one row in place, which notices a
/// database that takes no writes at all. While not writable, it proves
/// recovery with the write an audit insert is: a row in the audit table,
/// with its indexes and growth. An in-place rewrite can succeed on a nearly
/// full disk while audit inserts still fail, and clearing the flag on it let
/// requests through unaudited (AGENT-354). Failed attempts leave nothing; each
/// success is a `database_writes_recovered` row.
pub async fn probe(audit: &AuditRepository) {
    let health = audit.write_health();
    let attempt = health.begin();
    // The light write only detects failure; its success never clears one. A
    // failure being published while this probe chose the light write (after
    // `failed` takes its ticket, before it stores it) must still wait for an
    // audit row.
    let light = health.writable();
    let write = async {
        if light {
            audit.probe_write().await.map(|()| None)
        } else {
            audit.insert_recovery().await.map(Some)
        }
    };
    match tokio::time::timeout(PROBE_TIMEOUT, write).await {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(row))) => {
            // SQLite took the row: clear first, then mirror. A slow optional
            // mirror must not turn a committed write into a failure.
            health.succeeded(attempt);
            audit.mirror(&row).await;
        }
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
        health.succeeded(health.begin());
        assert!(health.writable());
    }

    #[test]
    fn a_write_begun_before_a_failure_cannot_clear_it() {
        // Codex review of AGENT-251: SQLite can commit a write just before the
        // file fails, and its task can resume after the failure is recorded.
        // That success proves nothing about the database now.
        let health = WriteHealth::default();
        let stale = health.begin();
        health.failed("audit", &"disk I/O error");
        health.succeeded(stale);
        assert!(!health.writable(), "a stale success reopened admission");
        let fresh = health.begin();
        health.succeeded(fresh);
        assert!(
            health.writable(),
            "a write begun after the failure proves recovery"
        );
    }

    #[test]
    fn a_later_failure_outranks_an_earlier_success_in_flight() {
        let health = WriteHealth::default();
        health.failed("audit", &"disk I/O error");
        let first = health.begin();
        health.failed("probe", &"disk I/O error");
        health.succeeded(first);
        assert!(!health.writable());
    }

    #[test]
    fn clones_share_one_flag() {
        let health = WriteHealth::default();
        let other = health.clone();
        health.failed("test", &"disk I/O error");
        assert!(!other.writable());
        other.succeeded(other.begin());
        assert!(health.writable());
    }
}
