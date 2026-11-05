use super::{Runtime, error::Failure};
use crate::auth_v2::AgentIdentity;
use crate::native_authority::{self as authority, effective::Snapshot};
use locksmith_mcp_transport::sessions::Scope;
use std::{
    collections::HashSet,
    sync::{Mutex, Weak, atomic::AtomicBool},
};
use tokio_util::sync::CancellationToken;

pub(super) struct Context {
    pub runtime: Weak<Runtime>,
    pub identity: AgentIdentity,
    pub name: String,
    pub scope: Scope,
    pub cancelled: CancellationToken,
    pub ready: AtomicBool,
    ids: Mutex<HashSet<String>>,
    pub pins: Mutex<crate::native_authority::effective::Pins>,
}
impl Context {
    pub fn new(
        runtime: Weak<Runtime>,
        identity: AgentIdentity,
        name: String,
        scope: Scope,
        cancelled: CancellationToken,
    ) -> Self {
        Self {
            runtime,
            identity,
            name,
            scope,
            cancelled,
            ready: AtomicBool::new(false),
            ids: Mutex::default(),
            pins: Mutex::default(),
        }
    }
    pub async fn current(&self) -> Result<(), Failure> {
        let runtime = self
            .runtime
            .upgrade()
            .ok_or(Failure(503, "shutting_down"))?;
        tokio::select! {
            biased;
            _ = self.cancelled.cancelled() => Err(Failure(404,"session_closed")),
            _ = runtime.stopped.cancelled() => Err(Failure(503,"shutting_down")),
            result = runtime.admit(&self.identity, &self.name) => {
                if result.is_ok_and(|scope| scope == self.scope) { Ok(()) }
                else { self.cancelled.cancel(); Err(Failure(404,"authority_changed")) }
            }
        }
    }
    pub fn list(&self, snapshot: &Snapshot) -> authority::Result<Vec<serde_json::Value>> {
        let source = &snapshot.current.source;
        if self.cancelled.is_cancelled()
            || self.scope.owner != self.identity.public_id
            || self.scope.connection != self.name
            || self.scope.authority
                != super::scope::authority(&source.instance, source.revision, source.agent_epoch)
        {
            self.cancelled.cancel();
            return Err(authority::Error("authority_changed"));
        }
        self.pins.lock().unwrap().list(snapshot)
    }
    pub fn remember(&self, id: &serde_json::Value, max: usize) -> Result<(), Failure> {
        let mut ids = self.ids.lock().unwrap();
        let key = id.to_string();
        if ids.contains(&key) {
            return Err(Failure(409, "request_id_reused"));
        }
        if ids.len() >= max {
            return Err(Failure(429, "request_id_limit"));
        }
        ids.insert(key);
        Ok(())
    }
}

#[cfg(test)]
#[path = "context_tests.rs"]
mod tests;
