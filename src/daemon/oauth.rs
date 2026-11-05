//! Refresh scopes outlive neither daemon return nor its canonical database lock.
use super::*;
use crate::oauth::refresh::RefreshOwner;

pub(super) async fn owned(
    config: AppConfig,
    coord: ShutdownCoordinator,
) -> Result<(), DaemonError> {
    let owner = RefreshOwner::default();
    let run = super::run_owned(config, coord.clone(), owner.clone());
    tokio::pin!(run);
    let result = tokio::select! {
        biased;
        _ = coord.shutdown_signal() => {
            owner.close();
            run.await
        }
        result = &mut run => result,
    };
    owner.close();
    coord.trigger();
    owner.wait().await;
    result
}

pub(super) struct Background {
    runtime: crate::app::OauthRuntime,
    catalog: Arc<ArcSwap<crate::registrations::Catalog>>,
    bindings: crate::repo::AgentCredentialRepository,
    log: Option<Arc<crate::operational_log_sink::OperationalLogEmitter>>,
}

impl Background {
    pub fn prepare(
        runtime: Option<&crate::app::OauthRuntime>,
        catalog: Option<&Arc<ArcSwap<crate::registrations::Catalog>>>,
        bindings: Option<&crate::repo::AgentCredentialRepository>,
        log: Option<&Arc<crate::operational_log_sink::OperationalLogEmitter>>,
    ) -> Option<Self> {
        Some(Self {
            runtime: runtime?.clone(),
            catalog: catalog?.clone(),
            bindings: bindings?.clone(),
            log: log.cloned(),
        })
    }

    pub fn spawn(self, coord: &ShutdownCoordinator) -> tokio::task::JoinHandle<()> {
        let rt = self.runtime;
        tokio::spawn(crate::oauth::refresh::run(
            rt.sessions,
            self.catalog,
            self.bindings,
            rt.sealing_key,
            rt.locks,
            self.log,
            coord.shutdown_signal(),
        ))
    }
}
