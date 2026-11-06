use serde::Serialize;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::Relaxed},
};

#[derive(Default)]
struct Counters {
    received: AtomicUsize,
    admitted: AtomicUsize,
    chunks: AtomicUsize,
    chunk_high_water: AtomicUsize,
    retained_high_water: AtomicUsize,
    active_bodies: AtomicUsize,
    budget: AtomicUsize,
}

/// Aggregate observations for this client, never a process-global heap bound.
#[derive(Clone, Default)]
pub struct Metrics(Arc<Counters>);
#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub received: usize,
    pub admitted: usize,
    pub chunks: usize,
    pub chunk_high_water: usize,
    pub retained_high_water: usize,
    pub active_bodies: usize,
}
impl Metrics {
    pub(crate) fn budget(&self, bytes: usize) {
        self.0.budget.store(bytes, Relaxed);
    }
    pub fn snapshot(&self) -> Snapshot {
        let c = &self.0;
        Snapshot {
            received: c.received.load(Relaxed),
            admitted: c.admitted.load(Relaxed),
            chunks: c.chunks.load(Relaxed),
            chunk_high_water: c.chunk_high_water.load(Relaxed),
            retained_high_water: c.retained_high_water.load(Relaxed),
            active_bodies: c.active_bodies.load(Relaxed),
        }
    }
    pub(crate) fn received(&self, n: usize) -> Result<(), crate::Error> {
        let total = self.0.received.fetch_add(n, Relaxed).saturating_add(n);
        self.0.chunks.fetch_add(1, Relaxed);
        self.0.chunk_high_water.fetch_max(n, Relaxed);
        let budget = self.0.budget.load(Relaxed);
        if budget != 0 && total > budget {
            return Err(crate::Error("aggregate_bytes"));
        }
        Ok(())
    }
    pub(crate) fn admitted(&self, n: usize) {
        self.0.admitted.fetch_add(n, Relaxed);
    }
    pub(crate) fn retained(&self, n: usize) {
        self.0.retained_high_water.fetch_max(n, Relaxed);
    }
    pub(crate) fn open(&self) {
        self.0.active_bodies.fetch_add(1, Relaxed);
    }
    pub(crate) fn close(&self) {
        self.0.active_bodies.fetch_sub(1, Relaxed);
    }
}
