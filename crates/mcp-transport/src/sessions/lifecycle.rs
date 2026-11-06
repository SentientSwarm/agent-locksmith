use super::{
    Error, OwnedTransport, Scoped,
    entry::{Entry, State},
};
use rmcp::transport::{
    WorkerTransport,
    common::server_side_http::session_id,
    streamable_http_server::session::{SessionId, local::create_local_session},
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

impl<T: Clone + Send + Sync + 'static> Scoped<T> {
    fn check_capacity(&self, registry: &super::pool::Registry<T>) -> Result<(), Error> {
        let config = &self.pool.0.config;
        let owner = registry
            .entries
            .values()
            .filter(|e| e.scope.owner == self.scope.owner)
            .count();
        let connection = registry
            .entries
            .values()
            .filter(|e| {
                e.scope.owner == self.scope.owner && e.scope.connection == self.scope.connection
            })
            .count();
        if registry.stopped || self.closed.is_cancelled() {
            return Err(Error::Unavailable);
        }
        if registry.entries.len() >= config.total
            || owner >= config.per_owner
            || connection >= config.per_connection
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub(crate) fn allocate(&self) -> Result<(SessionId, OwnedTransport<T>), Error> {
        let mut registry = self.pool.0.state.lock().unwrap();
        let config = &self.pool.0.config;
        self.check_capacity(&registry)?;
        let id = session_id();
        let (handle, worker) = create_local_session(id.clone(), config.sdk());
        let entry = Arc::new(Entry {
            id: id.clone(),
            scope: self.scope.clone(),
            metadata: self.metadata.clone(),
            closed: self.closed.clone(),
            handle,
            initialized: CancellationToken::new(),
            worker_done: CancellationToken::new(),
            done: CancellationToken::new(),
            pool: Arc::downgrade(&self.pool.0),
            state: std::sync::Mutex::new(State::default()),
        });
        registry.entries.insert(id.clone(), entry.clone());
        registry.metrics.workers_created += 1;
        let worker = WorkerTransport::spawn_with_ct(worker, entry.closed.child_token());
        let abort = worker.worker_abort_handle().expect("new SDK worker");
        watch(entry.clone(), config.clone(), abort);
        Ok((id, OwnedTransport::new(worker, entry)))
    }
}
fn watch<T: Send + Sync + 'static>(
    entry: Arc<Entry<T>>,
    config: super::Config,
    abort: tokio::task::AbortHandle,
) {
    let started = tokio::time::Instant::now();
    tokio::spawn(async move {
        tokio::select! {
            _ = entry.closed.cancelled() => {},
            _ = tokio::time::sleep_until(started + config.handshake.min(config.lifetime)) => entry.retire(),
            _ = entry.initialized.cancelled() => {
                tokio::select! {
                    _ = entry.closed.cancelled() => {},
                    _ = tokio::time::sleep_until(started + config.lifetime) => entry.retire(),
                }
            }
        }
        tokio::select! {
            _ = entry.worker_done.cancelled() => {},
            _ = tokio::time::sleep(config.cleanup_grace) => abort.abort(),
        }
    });
}
