use crate::{
    Error,
    observers::{Prepared, Sessions},
    process, setup,
};
use agent_locksmith::native_authority::runtime::Runtime;
use std::{ops::Deref, sync::Arc};
#[path = "running.rs"]
mod running;
use running::Running;

pub struct Store {
    pub pool: sqlx::SqlitePool,
}
pub struct Core {
    pub store: Store,
    pub prepared: Prepared,
    pub runtime: Arc<Runtime>,
}
impl Deref for Core {
    type Target = Runtime;
    fn deref(&self) -> &Runtime {
        &self.runtime
    }
}
pub struct Gateway {
    pub sessions: Sessions,
}
pub struct Fixture {
    pub core: Core,
    pub gateway: Gateway,
    pub identities: Vec<String>,
    pub url: String,
    pub bearer: String,
    pub(crate) directory: tempfile::TempDir,
    receiver: process::Guard,
    running: Running,
}
impl Fixture {
    pub async fn start(script: &str) -> Result<Self, Error> {
        Self::configured(script, 10_000).await
    }
    pub async fn configured(script: &str, request_ms: u64) -> Result<Self, Error> {
        let (s, receiver) = setup::prepare(script).await?;
        let authority = Arc::new(s.rt);
        let running = Running::start(&s.f, authority.clone(), request_ms).await?;
        Ok(Self {
            core: Core {
                store: Store {
                    pool: s.f.pool.clone(),
                },
                prepared: Prepared(s.f._dir.path().into()),
                runtime: authority,
            },
            gateway: Gateway {
                sessions: Sessions {
                    id: Default::default(),
                    owner: s.agent.clone(),
                    closed: running.closed.clone(),
                },
            },
            identities: vec![s.agent],
            url: running.url.clone(),
            bearer: s.f.bearer,
            directory: s.f._dir,
            receiver,
            running,
        })
    }
    pub fn arrivals(&self) -> Result<usize, Error> {
        let file = self.directory.path().join("effects.json");
        if !file.exists() {
            return Ok(0);
        }
        Ok(serde_json::from_slice::<Vec<serde_json::Value>>(&std::fs::read(file)?)?.len())
    }
    pub async fn finish(mut self) -> Result<(), Error> {
        self.core.owner.close();
        self.running.native.shutdown().await;
        self.core.owner.wait().await;
        self.running.finish().await?;
        self.receiver.0.kill()?;
        self.receiver.0.wait()?;
        Ok(())
    }
}
