use super::{Config, Error, Scope, entry::Entry};
use rmcp::transport::streamable_http_server::session::SessionId;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
    pub entries: usize,
    pub initializing: usize,
    pub active: usize,
    pub closing: usize,
    pub workers_created: u64,
    pub workers_joined: u64,
    pub services_created: u64,
    pub services_joined: u64,
    pub released: u64,
}
pub(crate) struct Registry<T> {
    pub entries: HashMap<SessionId, Arc<Entry<T>>>,
    pub metrics: Snapshot,
    pub stopped: bool,
}
pub(crate) struct Inner<T> {
    pub config: Config,
    pub state: Mutex<Registry<T>>,
}
pub struct Pool<T>(pub(crate) Arc<Inner<T>>);
pub struct Scoped<T> {
    pub(crate) pool: Pool<T>,
    pub(crate) scope: Scope,
    pub(crate) metadata: T,
    pub(crate) closed: CancellationToken,
}
impl<T> Clone for Pool<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T: Clone> Clone for Scoped<T> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            scope: self.scope.clone(),
            metadata: self.metadata.clone(),
            closed: self.closed.clone(),
        }
    }
}
impl<T> Pool<T> {
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self(Arc::new(Inner {
            config,
            state: Mutex::new(Registry {
                entries: HashMap::new(),
                metrics: Snapshot::default(),
                stopped: false,
            }),
        })))
    }
    /// The token belongs to this verified session; cancel it on disconnect.
    pub fn scoped(
        &self,
        scope: Scope,
        metadata: T,
        closed: CancellationToken,
    ) -> Result<Scoped<T>, Error> {
        scope.validate()?;
        Ok(Scoped {
            pool: self.clone(),
            scope,
            metadata,
            closed,
        })
    }
    pub fn snapshot(&self) -> Snapshot {
        let state = self.0.state.lock().unwrap();
        let mut result = state.metrics;
        result.entries = state.entries.len();
        for entry in state.entries.values() {
            if entry.closed.is_cancelled() {
                result.closing += 1;
            } else if entry.initialized.is_cancelled() {
                result.active += 1;
            } else {
                result.initializing += 1;
            }
        }
        result
    }
    /// Call after failed current authority with a verified identity. No secrets.
    pub fn invalidate(&self, owner: &str, connection: &str) {
        for entry in self.0.state.lock().unwrap().entries.values() {
            if entry.scope.owner == owner && entry.scope.connection == connection {
                entry.retire();
            }
        }
    }
    pub async fn shutdown(&self) {
        let entries = {
            let mut state = self.0.state.lock().unwrap();
            state.stopped = true;
            state.entries.values().cloned().collect::<Vec<_>>()
        };
        for entry in &entries {
            entry.retire();
        }
        for entry in entries {
            entry.done.cancelled().await;
        }
    }
}
impl<T: Clone> Scoped<T> {
    pub(crate) fn entry(&self, id: &SessionId) -> Result<Arc<Entry<T>>, Error> {
        let state = self.pool.0.state.lock().unwrap();
        let entry = state.entries.get(id).ok_or(Error::Unavailable)?;
        if entry.scope.owner != self.scope.owner || entry.scope.connection != self.scope.connection
        {
            return Err(Error::Unavailable);
        }
        if entry.scope.authority != self.scope.authority {
            entry.retire();
        }
        if entry.closed.is_cancelled() {
            return Err(Error::Unavailable);
        }
        Ok(entry.clone())
    }
    pub fn metadata(&self, id: &SessionId) -> Result<T, Error> {
        Ok(self.entry(id)?.metadata.clone())
    }
    pub fn cancellation(&self, id: &SessionId) -> Result<CancellationToken, Error> {
        Ok(self.entry(id)?.closed.clone())
    }
    /// Signal only; completion can be awaited separately without owning cleanup.
    pub fn retire(&self, id: &SessionId) {
        let state = self.pool.0.state.lock().unwrap();
        if let Some(entry) = state.entries.get(id)
            && entry.scope.owner == self.scope.owner
            && entry.scope.connection == self.scope.connection
        {
            entry.retire();
        }
    }
    pub async fn wait_retired(&self, id: &SessionId) {
        let done = self
            .pool
            .0
            .state
            .lock()
            .unwrap()
            .entries
            .get(id)
            .and_then(|entry| {
                (entry.scope.owner == self.scope.owner
                    && entry.scope.connection == self.scope.connection)
                    .then(|| entry.done.clone())
            });
        if let Some(done) = done {
            done.cancelled().await;
        }
    }
}
