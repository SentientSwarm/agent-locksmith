//! Owner-controlled fixture upgrade: real SQLite agent and explicit sealed selections.
#![allow(dead_code)] // Each integration target uses the needed fixture entry point.
use agent_locksmith::{
    app::build_app_full_with_phase_j,
    auth_v2::BearerAuthenticator,
    config::AppConfig,
    migrations::open_and_migrate,
    registrations::{AuthSpec, Catalog},
    repo::{AgentCredentialRepository, AgentRepository, CredentialSecretsRepository},
    secret::{CredentialSealingKey, resolve_tool_creds_sync_env_only},
};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tempfile::TempDir;

pub struct Fixture {
    pub server: TestServer,
    #[allow(dead_code)] // Shared fixture: readiness cases do not send bearer headers.
    pub bearer: String,
    _dir: TempDir,
}

async fn application(config: AppConfig) -> (axum::Router, String, TempDir) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("registered.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let (pid, token) = agents
        .create("fixture", None, None, None, None, None)
        .await
        .unwrap();
    let id = agents
        .get_active_by_public_id(&pid)
        .await
        .unwrap()
        .unwrap()
        .id;
    let selections = AgentCredentialRepository::new(pool.clone());
    let registrations = agent_locksmith::registrations::RegistrationRepository::new(pool.clone());
    let secrets = CredentialSecretsRepository::new(pool);
    let key = CredentialSealingKey::generate().unwrap();
    let resolved = resolve_tool_creds_sync_env_only(&config);
    for tool in &config.tools {
        registrations
            .create(&agent_locksmith::registrations::Registration::new(
                tool.name.clone(),
                agent_locksmith::registrations::Kind::Tool,
                tool.description.clone(),
                tool.upstream.clone(),
                AuthSpec::None,
            ))
            .await
            .unwrap();
        let spec = if let Some(auth) = &tool.auth {
            let value = resolved
                .get(&tool.name)
                .map(|s| s.expose_secret().as_bytes())
                .unwrap_or(b"");
            let (ciphertext, nonce) = key.seal(value).unwrap();
            AuthSpec::StoredHeader {
                header: auth.header.clone(),
                secret_ref: secrets.insert(&ciphertext, &nonce).await.unwrap(),
            }
        } else {
            AuthSpec::None
        };
        selections.set(id, &tool.name, &spec).await.unwrap();
    }
    let names: Vec<_> = config.tools.iter().map(|t| t.name.clone()).collect();
    agents
        .update_policy(&pid, Some(Some(names)), None, None, None)
        .await
        .unwrap();
    let app = build_app_full_with_phase_j(
        Arc::new(ArcSwap::from_pointee(config)),
        None,
        Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        Some(Arc::new(
            BearerAuthenticator::with_audit(agents, None).unwrap(),
        )),
        None,
        Arc::new(ArcSwap::from_pointee(Catalog::default())),
        None,
        Some(selections),
        Some(key),
        Some(secrets),
    );
    (
        app,
        format!("Bearer lk_{pid}.{}", token.expose_secret()),
        dir,
    )
}

pub async fn setup(config: AppConfig) -> Fixture {
    let (app, bearer, dir) = application(config).await;
    Fixture {
        server: TestServer::new(app),
        bearer,
        _dir: dir,
    }
}

pub async fn spawn(config: AppConfig) -> (String, String) {
    let (app, bearer, dir) = application(config).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _dir = dir;
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), bearer)
}
