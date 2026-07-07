//! Non-blocking operational-log emitter — Phase J / M2 (LOG-2/LOG-4, WEM-447).
//!
//! Hot paths (proxy, admin handlers, OAuth refresh, config reload) call
//! [`OperationalLogEmitter::emit`], which pushes a record onto a bounded
//! [`tokio::sync::mpsc`] channel and returns immediately. A single
//! background task drains the channel into [`OperationalLogStore`]. This
//! mirrors the audit JSONL sink's backpressure discipline: never block the
//! caller. If the channel is full (drain task fell behind), the record is
//! DROPPED and a counter is bumped + a rate-safe warn is logged, rather
//! than stalling the request.
//!
//! **Secret-free by contract (LOG-4).** Callers pass event names +
//! non-secret context only. A credential value must never be handed to
//! `emit` — there is no code path that unseals or forwards one here.

use crate::repo::{LogComponent, LogLevel, OperationalLogStore};
use serde_json::Value as Json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::warn;

/// One queued operational-log record. Internal — the public surface is
/// [`OperationalLogEmitter::emit`].
struct OperationalLogEvent {
    level: LogLevel,
    component: LogComponent,
    event: String,
    message: String,
    fields: Option<Json>,
}

/// Default channel depth. Deep enough to absorb bursts from the admin
/// surface and proxy degradations without dropping under normal load;
/// bounded so a stalled drain task can't grow memory unboundedly.
pub const DEFAULT_CAPACITY: usize = 1024;

/// Cheap-to-clone handle used by every emit site. Cloning shares the
/// underlying channel sender + drop counter.
#[derive(Clone)]
pub struct OperationalLogEmitter {
    tx: mpsc::Sender<OperationalLogEvent>,
    dropped: Arc<AtomicU64>,
}

impl OperationalLogEmitter {
    /// Build an emitter over a fresh bounded channel of `capacity`,
    /// returning the emitter and the receiver end. The caller is
    /// responsible for draining the receiver (production wires
    /// [`OperationalLogEmitter::spawn`]; tests may hold the receiver
    /// undrained to exercise the drop path).
    fn new(capacity: usize) -> (Self, mpsc::Receiver<OperationalLogEvent>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Build an emitter and spawn the background drain task that writes
    /// every received record into `store`. The task exits when all
    /// emitter clones are dropped (channel closed) — it needs no separate
    /// shutdown signal because the writes are cheap and idempotent to
    /// abandon.
    pub fn spawn(store: OperationalLogStore, capacity: usize) -> Self {
        let (emitter, rx) = Self::new(capacity);
        tokio::spawn(drain_loop(rx, store));
        emitter
    }

    /// Enqueue an operational-log record without blocking. On a full
    /// channel the record is dropped and the drop counter bumped — the
    /// caller (a hot path) is never stalled. No secret value may be
    /// passed in any argument (LOG-4).
    pub fn emit(
        &self,
        level: LogLevel,
        component: LogComponent,
        event: impl Into<String>,
        message: impl Into<String>,
        fields: Option<Json>,
    ) {
        let ev = OperationalLogEvent {
            level,
            component,
            event: event.into(),
            message: message.into(),
            fields,
        };
        match self.tx.try_send(ev) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(ev)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                warn!(
                    component = ev.component.as_str(),
                    event = %ev.event,
                    dropped_total = n,
                    "operational-log channel full; dropping record"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("operational-log drain task gone; dropping record");
            }
        }
    }

    /// Number of records dropped due to a full channel since startup.
    /// Exposed for tests and future health surfacing.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Drain the channel into the store until all senders are dropped.
async fn drain_loop(mut rx: mpsc::Receiver<OperationalLogEvent>, store: OperationalLogStore) {
    while let Some(ev) = rx.recv().await {
        if let Err(e) = store
            .insert(
                ev.level,
                ev.component,
                &ev.event,
                &ev.message,
                ev.fields.as_ref(),
            )
            .await
        {
            warn!(error = %e, event = %ev.event, "operational-log insert failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::open_and_migrate;
    use crate::repo::LogFilter;
    use serde_json::json;
    use tempfile::TempDir;

    async fn fresh_store() -> (TempDir, OperationalLogStore) {
        let dir = TempDir::new().unwrap();
        let pool = open_and_migrate(&dir.path().join("db.sqlite"))
            .await
            .unwrap();
        (dir, OperationalLogStore::new(pool))
    }

    #[tokio::test]
    async fn emit_drain_query_sees_the_row() {
        let (_d, store) = fresh_store().await;
        let emitter = OperationalLogEmitter::spawn(store.clone(), 16);
        emitter.emit(
            LogLevel::Warn,
            LogComponent::Oauth,
            "oauth_refresh_degraded",
            "refresh failed; session marked degraded",
            Some(json!({ "registration": "codex" })),
        );
        // Poll until the drain task has committed the row.
        let mut seen = Vec::new();
        for _ in 0..50 {
            seen = store.query(&LogFilter::default()).await.unwrap();
            if !seen.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(seen.len(), 1, "drained record must be queryable");
        assert_eq!(seen[0].component, "oauth");
        assert_eq!(seen[0].event, "oauth_refresh_degraded");
    }

    #[tokio::test]
    async fn full_channel_drops_without_blocking() {
        // Undrained receiver held so the channel stays full.
        let (emitter, _rx) = OperationalLogEmitter::new(2);
        // Emit well past capacity — each call must return immediately.
        for i in 0..10 {
            emitter.emit(
                LogLevel::Info,
                LogComponent::Proxy,
                "burst",
                format!("event {i}"),
                None,
            );
        }
        assert!(
            emitter.dropped_count() >= 8,
            "records beyond capacity must be dropped, got {}",
            emitter.dropped_count()
        );
    }
}
