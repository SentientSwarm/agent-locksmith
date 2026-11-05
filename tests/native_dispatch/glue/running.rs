use crate::{Error, observers};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
pub struct Running {
    pub native: Arc<agent_locksmith::native::Runtime>,
    pub closed: CancellationToken,
    pub url: String,
    stop: CancellationToken,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    observer: tokio::task::JoinHandle<()>,
}
impl Running {
    pub async fn start(
        f: &crate::native::Fixture,
        authority: Arc<agent_locksmith::native_authority::runtime::Runtime>,
        request_ms: u64,
    ) -> Result<Self, Error> {
        let native = native(f, authority, request_ms);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!(
            "http://{}/mcp/native{}",
            listener.local_addr()?,
            if crate::COMPACT { "/compact" } else { "" }
        );
        let app = router(f, &native);
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stopped.cancelled_owned())
                .await
        });
        let closed = CancellationToken::new();
        let observer = observers::retired(native.clone(), closed.clone(), stop.clone());
        Ok(Self {
            native,
            closed,
            url,
            stop,
            server,
            observer,
        })
    }
    pub async fn finish(self) -> Result<(), Error> {
        self.stop.cancel();
        self.server.await??;
        self.observer.await?;
        Ok(())
    }
}

fn router(f: &crate::native::Fixture, rt: &Arc<agent_locksmith::native::Runtime>) -> axum::Router {
    agent_locksmith::app::build_app_full_with_native(
        Arc::new(arc_swap::ArcSwap::from_pointee(
            agent_locksmith::config::parse_config_str("listen:\n  port: 9200\n").unwrap(),
        )),
        Some(agent_locksmith::repo::AuditRepository::new(f.pool.clone())),
        Arc::new(arc_swap::ArcSwap::from_pointee(Default::default())),
        None,
        Some(Arc::new(
            agent_locksmith::auth_v2::BearerAuthenticator::new(f.agents.clone()).unwrap(),
        )),
        Some(f.repo.clone()),
        f.catalog.clone(),
        None,
        Some(f.bindings.clone()),
        None,
        None,
        None,
        None,
        rt.clone(),
    )
}

fn native(
    f: &crate::native::Fixture,
    authority: Arc<agent_locksmith::native_authority::runtime::Runtime>,
    request_ms: u64,
) -> Arc<agent_locksmith::native::Runtime> {
    let config = agent_locksmith::native::config::Config {
        request_ms,
        ..Default::default()
    };
    agent_locksmith::native::Runtime::with_authority(
        config,
        Some(f.repo.clone()),
        f.catalog.clone(),
        Some(authority),
    )
}
