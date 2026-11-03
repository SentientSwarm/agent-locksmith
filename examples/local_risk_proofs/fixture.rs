//! Temporary SQLite + real application; only the upstream is a test double.
use super::application::app;
use agent_locksmith::app::OauthRuntime;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub struct Store {
    _dir: TempDir,
    pub pool: SqlitePool,
    pub agents: AgentRepository,
    pub overrides: AgentCredentialRepository,
    pub registrations: Arc<RegistrationRepository>,
}

pub struct Fixture {
    pub store: Store,
    pub catalog: Arc<ArcSwap<Catalog>>,
    pub agent_id: i64,
    pub public_id: String,
    pub mock: MockServer,
    server: TestServer,
    bearer: String,
}

pub fn env_auth(is_header: bool, name: &str) -> AuthSpec {
    if is_header {
        AuthSpec::Header {
            header: "x-api-key".into(),
            env_var: name.into(),
        }
    } else {
        AuthSpec::Bearer {
            env_var: name.into(),
        }
    }
}

pub async fn register(repo: &RegistrationRepository, name: &str, uri: &str, auth: AuthSpec) {
    let row = Registration::new(
        name.into(),
        Kind::Tool,
        "Local proof".into(),
        uri.into(),
        auth,
    );
    repo.create(&row).await.unwrap();
}

async fn mount_accounts(mock: &MockServer, is_header: bool) {
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("no-approved-account"))
        .with_priority(10)
        .mount(mock)
        .await;
    for (key, account) in [("proof-default", "default"), ("proof-selected", "selected")] {
        let (name, value) = if is_header {
            ("x-api-key", key.to_string())
        } else {
            ("authorization", format!("Bearer {key}"))
        };
        Mock::given(method("GET"))
            .and(header(name, value))
            .respond_with(ResponseTemplate::new(200).set_body_string(account))
            .with_priority(1)
            .mount(mock)
            .await;
    }
}

async fn store(is_header: bool, uri: &str) -> Store {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("proof.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let overrides = AgentCredentialRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    register(
        &registrations,
        "proof",
        uri,
        env_auth(is_header, "UNUSED_PROOF_DEFAULT"),
    )
    .await;
    Store {
        _dir: dir,
        pool,
        agents,
        overrides,
        registrations,
    }
}

async fn identity(agents: &AgentRepository, unrestricted: bool) -> (i64, String, String) {
    let allow = ["proof".to_string()];
    let (public_id, secret) = agents
        .create(
            "proof-agent",
            None,
            if unrestricted { None } else { Some(&allow) },
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let id = agents.get_by_name("proof-agent").await.unwrap().unwrap().id;
    let bearer = format!("Bearer lk_{public_id}.{}", secret.expose_secret());
    (id, public_id, bearer)
}

impl Fixture {
    pub async fn new(is_header: bool, unrestricted: bool) -> Self {
        let mock = MockServer::start().await;
        mount_accounts(&mock, is_header).await;
        let store = store(is_header, &mock.uri()).await;
        let catalog = Arc::new(ArcSwap::from_pointee(
            Catalog::from_repo(&store.registrations).await.unwrap(),
        ));
        let (agent_id, public_id, bearer) = identity(&store.agents, unrestricted).await;
        let server = app(&store, catalog.clone(), None);
        Self {
            store,
            catalog,
            agent_id,
            public_id,
            mock,
            server,
            bearer,
        }
    }

    pub fn activate_oauth(&mut self, runtime: OauthRuntime) {
        self.server = app(&self.store, self.catalog.clone(), Some(runtime));
    }

    pub async fn request(&self, name: &str) -> Value {
        let before = self
            .mock
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/check")
            .count();
        let response = self
            .server
            .get(&format!("/api/{name}/check"))
            .add_header("authorization", &self.bearer)
            .await;
        let after = self
            .mock
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/check")
            .count();
        json!({ "status": response.status_code().as_u16(),
            "upstream_calls": after - before,
            "account": if after > before { Some(response.text()) } else { None } })
    }

    pub async fn refresh_catalog(&self) {
        self.catalog.store(Arc::new(
            Catalog::from_repo(&self.store.registrations).await.unwrap(),
        ));
    }
}
