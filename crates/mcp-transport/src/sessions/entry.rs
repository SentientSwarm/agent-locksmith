use super::{Scope, pool::Inner};
use rmcp::transport::streamable_http_server::session::{SessionId, local::LocalSessionHandle};
use std::sync::{Arc, Mutex, Weak};
use tokio_util::sync::CancellationToken;

pub(crate) struct Entry<T> {
    pub id: SessionId,
    pub scope: Scope,
    pub metadata: T,
    pub closed: CancellationToken,
    pub initialized: CancellationToken,
    pub worker_done: CancellationToken,
    pub done: CancellationToken,
    pub handle: LocalSessionHandle,
    pub pool: Weak<Inner<T>>,
    pub state: Mutex<State>,
}
#[derive(Default)]
pub(crate) struct State {
    pub outer_started: bool,
    pub outer_done: bool,
    pub worker_done: bool,
    pub messages: usize,
    pub streams: usize,
    pub request_streams: usize,
    pub get_used: bool,
}
impl<T> Entry<T> {
    pub fn retire(&self) {
        self.closed.cancel();
    }
    pub fn complete(self: &Arc<Self>, worker: bool) {
        if worker {
            self.worker_done.cancel();
        }
        let Some(pool) = self.pool.upgrade() else {
            return;
        };
        let mut registry = pool.state.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        if worker && !state.worker_done {
            state.worker_done = true;
            registry.metrics.workers_joined += 1;
            self.worker_done.cancel();
        } else if !worker && !state.outer_done {
            state.outer_done = true;
            registry.metrics.services_joined += 1;
        }
        drop(state);
        drop(registry);
        self.try_release();
    }
    pub fn try_release(&self) {
        let Some(pool) = self.pool.upgrade() else {
            return;
        };
        let mut registry = pool.state.lock().unwrap();
        let state = self.state.lock().unwrap();
        if state.worker_done
            && (!state.outer_started || state.outer_done)
            && state.streams == 0
            && registry.entries.remove(&self.id).is_some()
        {
            registry.metrics.released += 1;
            self.done.cancel();
        }
    }
}
