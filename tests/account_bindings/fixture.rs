use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::audit::AuditRepository;
use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository};
use arc_swap::ArcSwap;
use axum_test::{TestResponse, TestServer};
use secrecy::ExposeSecret;
use sqlx::SqlitePool;
use std::sync::{Arc, Once};
use tempfile::TempDir;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method},
};

pub const X: &str = "D1_TEST_ACCOUNT_X";
pub const Y: &str = "D1_TEST_ACCOUNT_Y";
pub const EMPTY: &str = "D1_TEST_EMPTY";
pub const MISSING: &str = "D1_TEST_MISSING";
pub const SENTINELS: [&str; 3] = ["d1-private-X", "d1-private-Y", "d1-private-template"];

pub struct Agent {
    pub id: i64,
    pub public_id: String,
    pub bearer: String,
}
pub struct Fixture {
    _dir: TempDir,
    pub pool: SqlitePool,
    pub agents: AgentRepository,
    pub bindings: AgentCredentialRepository,
    pub registrations: Arc<RegistrationRepository>,
    pub catalog: Arc<ArcSwap<Catalog>>,
    pub audit: AuditRepository,
    pub mock: MockServer,
    pub server: TestServer,
}

pub fn env_auth(is_header: bool, env_var: &str) -> AuthSpec {
    if is_header {
        AuthSpec::Header {
            header: "x-api-key".into(),
            env_var: env_var.into(),
        }
    } else {
        AuthSpec::Bearer {
            env_var: env_var.into(),
        }
    }
}

fn environment() {
    static INIT: Once = Once::new();
    INIT.call_once(|| unsafe {
        std::env::set_var(X, SENTINELS[0]);
        std::env::set_var(Y, SENTINELS[1]);
        std::env::set_var(EMPTY, "");
        std::env::remove_var(MISSING);
    });
}

async fn accounts(mock: &MockServer, is_header: bool) {
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("UNAPPROVED"))
        .with_priority(10)
        .mount(mock)
        .await;
    for (secret, account) in SENTINELS.into_iter().zip(["X", "Y", "TEMPLATE"]) {
        let (key, value) = if is_header {
            ("x-api-key", secret.to_string())
        } else {
            ("authorization", format!("Bearer {secret}"))
        };
        Mock::given(method("GET"))
            .and(header(key, value))
            .respond_with(ResponseTemplate::new(200).set_body_string(account))
            .with_priority(1)
            .mount(mock)
            .await;
    }
}

impl Fixture {
    pub async fn new(is_header: bool) -> Self {
        environment();
        let dir = TempDir::new().unwrap();
        let pool = open_and_migrate(&dir.path().join("selection.db"))
            .await
            .unwrap();
        let agents = AgentRepository::new(pool.clone());
        let bindings = AgentCredentialRepository::new(pool.clone());
        let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
        let audit = AuditRepository::new(pool.clone());
        let mock = MockServer::start().await;
        accounts(&mock, is_header).await;
        let catalog = catalog(&registrations, &mock, is_header).await;
        let server = crate::application::server(
            &agents,
            Some(bindings.clone()),
            &registrations,
            catalog.clone(),
            audit.clone(),
        );
        Self {
            _dir: dir,
            pool,
            agents,
            bindings,
            registrations,
            catalog,
            audit,
            mock,
            server,
        }
    }

    pub async fn agent(&self, name: &str) -> Agent {
        let (public_id, secret) = self
            .agents
            .create(name, None, Some(&["api".into()]), None, None, None)
            .await
            .unwrap();
        let id = self.agents.get_by_name(name).await.unwrap().unwrap().id;
        Agent {
            id,
            bearer: format!("Bearer lk_{public_id}.{}", secret.expose_secret()),
            public_id,
        }
    }

    pub async fn bind(&self, agent: &Agent, spec: &AuthSpec) {
        self.bindings.set(agent.id, "api", spec).await.unwrap();
    }

    pub async fn call(&self, agent: &Agent) -> TestResponse {
        self.server
            .get("/api/api/check")
            .add_header("authorization", &agent.bearer)
            .add_header("x-api-key", "caller-must-not-be-upstream")
            .await
    }

    pub async fn count(&self) -> usize {
        self.mock.received_requests().await.unwrap().len()
    }
}

async fn catalog(
    registrations: &RegistrationRepository,
    mock: &MockServer,
    is_header: bool,
) -> Arc<ArcSwap<Catalog>> {
    registrations
        .create(&Registration::new(
            "api".into(),
            Kind::Tool,
            "Selection test".into(),
            mock.uri(),
            env_auth(is_header, "TEMPLATE"),
        ))
        .await
        .unwrap();
    Arc::new(ArcSwap::from_pointee(
        Catalog::from_repo(registrations).await.unwrap(),
    ))
}
