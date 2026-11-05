use agent_locksmith::{
    app,
    auth_v2::BearerAuthenticator,
    registrations::{AuthSpec, Catalog, RegistrationRepository},
    repo::{AgentCredentialRepository, AgentRepository},
};
use arc_swap::ArcSwap;
use secrecy::ExposeSecret;
use std::sync::Arc;

pub async fn caller(
    pool: &sqlx::SqlitePool,
) -> (AgentRepository, AgentCredentialRepository, i64, String) {
    let agents = AgentRepository::new(pool.clone());
    let (public_id, secret) = agents
        .create(
            "caller",
            None,
            Some(&["native".into(), "other".into()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let id = agents.get_by_name("caller").await.unwrap().unwrap().id;
    let bindings = AgentCredentialRepository::new(pool.clone());
    for name in ["native", "other"] {
        bindings.set(id, name, &AuthSpec::None).await.unwrap();
    }
    let bearer = format!("Bearer lk_{public_id}.{}", secret.expose_secret());
    (agents, bindings, id, bearer)
}
pub fn router(
    cfg: agent_locksmith::config::AppConfig,
    repo: &Arc<RegistrationRepository>,
    agents: &AgentRepository,
    bindings: &AgentCredentialRepository,
    catalog: &Arc<ArcSwap<Catalog>>,
    runtime: &Arc<agent_locksmith::native::Runtime>,
) -> axum::Router {
    app::build_app_full_with_native(
        Arc::new(ArcSwap::from_pointee(cfg)),
        None,
        Arc::new(ArcSwap::from_pointee(Default::default())),
        None,
        Some(Arc::new(BearerAuthenticator::new(agents.clone()).unwrap())),
        Some(repo.clone()),
        catalog.clone(),
        None,
        Some(bindings.clone()),
        None,
        None,
        None,
        None,
        runtime.clone(),
    )
}

pub async fn catalog(repo: &RegistrationRepository) -> Arc<ArcSwap<Catalog>> {
    Arc::new(ArcSwap::from_pointee(
        Catalog::from_repo(repo).await.unwrap(),
    ))
}

pub async fn store() -> (
    tempfile::TempDir,
    sqlx::SqlitePool,
    Arc<RegistrationRepository>,
) {
    let dir = tempfile::tempdir().unwrap();
    let pool = agent_locksmith::migrations::open_and_migrate(&dir.path().join("state.db"))
        .await
        .unwrap();
    let repo = Arc::new(RegistrationRepository::new(pool.clone()));
    for name in ["native", "other"] {
        repo.create(&super::native(name)).await.unwrap();
    }
    (dir, pool, repo)
}
