use super::{config::Config, context::Context, error::Failure};
use crate::{
    auth_v2::AgentIdentity,
    registrations::{Catalog, RegistrationRepository, admission::activation},
};
use arc_swap::ArcSwap;
use locksmith_mcp_transport::sessions::{Pool, Scope};
use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinHandle};
use tokio_util::sync::CancellationToken;

pub struct Runtime {
    pub(super) config: Config,
    pub(super) pool: Pool<Arc<Context>>,
    pub(super) ingress: Semaphore,
    pub(super) stopped: CancellationToken,
    pub(super) contexts: Mutex<Vec<Weak<Context>>>,
    repo: Option<Arc<RegistrationRepository>>,
    catalog: Arc<ArcSwap<Catalog>>,
}
impl Runtime {
    pub fn new(
        config: Config,
        repo: Option<Arc<RegistrationRepository>>,
        catalog: Arc<ArcSwap<Catalog>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            pool: Pool::new(config.sessions()).expect("validated session limits"),
            ingress: Semaphore::new(config.ingress),
            stopped: CancellationToken::new(),
            config,
            repo,
            catalog,
            contexts: Mutex::default(),
        })
    }
    pub(super) async fn admit(
        &self,
        identity: &AgentIdentity,
        name: &str,
    ) -> Result<Scope, Failure> {
        let result = self.read_scope(identity, name).await;
        if result.is_err() {
            self.pool.invalidate(&identity.public_id, name);
        }
        result
    }
    async fn read_scope(&self, identity: &AgentIdentity, name: &str) -> Result<Scope, Failure> {
        if self.stopped.is_cancelled() {
            return Err(Failure(503, "shutting_down"));
        }
        let repo = self
            .repo
            .as_ref()
            .ok_or(Failure(503, "native_store_unavailable"))?;
        let mut rows = repo
            .native_admissions(identity, Some(name))
            .await
            .map_err(|_| Failure(503, "native_store_unavailable"))?;
        let row = rows.pop().ok_or(Failure(404, "connection_unavailable"))?;
        eligible(&row, &self.catalog.load())?;
        configuration(&row.registration)?;
        Ok(Scope {
            owner: identity.public_id.clone(),
            connection: name.into(),
            authority: format!("{}:{}:{}", row.instance, row.revision, row.epoch),
        })
    }
    pub fn start(
        self: &Arc<Self>,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> JoinHandle<()> {
        let runtime = self.clone();
        tokio::spawn(async move {
            tokio::pin!(shutdown);
            tokio::select! {
                biased;
                _ = &mut shutdown => {},
                _ = async {
                    loop {
                        runtime.sweep().await;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                } => {},
            }
            runtime.shutdown().await;
        })
    }
    async fn sweep(&self) {
        let contexts = {
            let mut contexts = self.contexts.lock().unwrap();
            contexts.retain(|c| c.strong_count() > 0);
            contexts
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        for context in contexts {
            if tokio::time::timeout(Duration::from_secs(1), context.current())
                .await
                .is_err()
            {
                context.cancelled.cancel();
            }
        }
    }
    pub async fn shutdown(&self) {
        self.stopped.cancel();
        self.ingress.close();
        self.pool.shutdown().await;
        let s = self.pool.snapshot();
        tracing::info!(
            entries = s.entries,
            workers_created = s.workers_created,
            workers_joined = s.workers_joined,
            services_created = s.services_created,
            services_joined = s.services_joined,
            released = s.released,
            "native sessions joined"
        );
    }
    pub fn snapshot(&self) -> locksmith_mcp_transport::sessions::Snapshot {
        self.pool.snapshot()
    }
}

fn eligible(
    row: &crate::registrations::admission::HttpAdmission,
    catalog: &Catalog,
) -> Result<(), Failure> {
    if !row.agent_active {
        return Err(Failure(401, "agent_inactive"));
    }
    if row.grant.is_err() {
        return Err(Failure(403, "connection_not_allowed"));
    }
    if row.registration.disabled {
        return Err(Failure(404, "connection_unavailable"));
    }
    if activation(&row.registration, Some(catalog)) != "active" {
        return Err(Failure(503, "connection_not_active"));
    }
    if row.account.is_none() {
        return Err(Failure(403, "account_selection_required"));
    }
    Ok(())
}
fn configuration(registration: &crate::registrations::Registration) -> Result<(), Failure> {
    crate::registrations::protocol::validate(
        registration.protocol,
        registration.mcp.as_ref(),
        registration.kind,
        registration.egress,
        &registration.upstream,
        Some(&registration.metadata),
    )
    .map_err(|_| Failure(503, "invalid_native_configuration"))?;
    Ok(())
}
