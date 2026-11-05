use super::{
    Error, Result,
    destination::Listeners,
    source::{self, Current},
    store,
};
use crate::{
    oauth::refresh::RefreshOwner,
    registrations::{Catalog, RegistrationRepository},
    secret::CredentialSealingKey,
};
use arc_swap::ArcSwap;
use locksmith_mcp_transport::Certificate;
use serde_json::{Value, json};
use sqlx::SqliteConnection;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct Runtime {
    pub repo: Arc<RegistrationRepository>,
    pub catalog: Arc<ArcSwap<Catalog>>,
    pub key: Option<CredentialSealingKey>,
    pub roots: Vec<Certificate>,
    pub run: String,
    pub listeners: Listeners,
    pub owner: RefreshOwner,
    pub slots: Semaphore,
}
impl Runtime {
    pub async fn new(
        repo: Arc<RegistrationRepository>,
        catalog: Arc<ArcSwap<Catalog>>,
        key: Option<CredentialSealingKey>,
        roots: Vec<Certificate>,
        owner: RefreshOwner,
    ) -> Result<Self> {
        let run = store::token(&mut *repo.pool.acquire().await?).await?;
        Ok(Self {
            repo,
            catalog,
            key,
            roots,
            run,
            listeners: Listeners::default(),
            owner,
            slots: Semaphore::new(8),
        })
    }
    pub async fn current(
        &self,
        c: &mut SqliteConnection,
        agent: &str,
        name: &str,
    ) -> Result<Current> {
        source::current(&self.repo, &self.catalog.load_full(), c, agent, name).await
    }
    pub async fn snapshot(&self, agent: &str, name: &str) -> Result<Value> {
        let mut tx = self.repo.pool.begin().await?;
        let current = self.current(&mut tx, agent, name).await?;
        let observation = store::observation(&mut tx, &current, &self.run).await?;
        let revision = store::revision(&mut tx, &current).await?;
        let tools = super::grants::entries(&mut tx, &current).await?;
        tx.commit().await?;
        Ok(
            json!({"source":current.source,"observation":observation,"grant_revision":revision,
            "tools":tools,"prepared_only":true,"callable":false}),
        )
    }
    pub async fn scoped<F: std::future::Future<Output = Result<Value>>>(
        &self,
        future: F,
    ) -> Result<Value> {
        self.owner
            .run(async {
                let _permit = self
                    .slots
                    .try_acquire()
                    .map_err(|_| Error("observation_capacity"))?;
                tokio::time::timeout(std::time::Duration::from_secs(10), future)
                    .await
                    .map_err(|_| Error("operation_deadline"))?
            })
            .await
            .ok_or(Error("shutting_down"))?
    }
}
pub fn roots(path: Option<&std::path::Path>) -> Result<Vec<Certificate>> {
    use std::io::Read;
    let Some(path) = path else {
        return Ok(vec![]);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| Error("upstream_roots_invalid"))?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("upstream_roots_invalid"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(Error("upstream_roots_invalid"));
    }
    let roots =
        Certificate::from_pem_bundle(&bytes).map_err(|_| Error("upstream_roots_invalid"))?;
    if roots.is_empty() {
        return Err(Error("upstream_roots_invalid"));
    }
    Ok(roots)
}
