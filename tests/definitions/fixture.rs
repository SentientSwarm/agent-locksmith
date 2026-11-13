#![allow(dead_code)]
use agent_locksmith::{
    admin::{
        AdminService,
        uds::{UdsState, build_router},
    },
    argon2_helper,
    auth_v2::{BearerAuthenticator, OperatorAuthenticator},
    config::parse_config_str,
    migrations::open_and_migrate,
    registrations::RegistrationRepository,
    repo::{AgentRepository, BootstrapTokenRepository},
    token,
};
use agent_locksmith::{repo::CredentialSecretsRepository, secret::CredentialSealingKey};
use arc_swap::ArcSwap;
use axum_test::{TestResponse, TestServer};
use serde_json::{Value, json};
use std::sync::Arc;

pub struct Fixture {
    pub server: TestServer,
    pub pool: sqlx::SqlitePool,
    pub token: String,
    pub repo: Arc<RegistrationRepository>,
    pub dir: tempfile::TempDir,
}
impl Fixture {
    pub async fn new() -> Self {
        Self::with_catalog(false).await
    }
    pub async fn with_catalog(catalog: bool) -> Self {
        Self::with_options(catalog, None).await
    }
    pub async fn with_options(
        catalog: bool,
        op: Option<Arc<agent_locksmith::secret::OpResolver>>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pool = open_and_migrate(&dir.path().join("state.db"))
            .await
            .unwrap();
        let (operator_auth, token) = operator(dir.path());
        let repo = Arc::new(RegistrationRepository::new(pool.clone()));
        let mut state = state(&pool, operator_auth, repo.clone());
        state.op_resolver = op;
        if catalog {
            state.catalog = Some(Arc::new(ArcSwap::from_pointee(
                agent_locksmith::registrations::Catalog::from_repo(&repo)
                    .await
                    .unwrap(),
            )));
        }
        Self {
            server: TestServer::new(build_router(state)),
            pool,
            token,
            repo,
            dir,
        }
    }
    pub async fn import(&self, value: &Value) -> TestResponse {
        self.server
            .put(&path(value))
            .add_header("authorization", &self.token)
            .json(value)
            .await
    }
    pub async fn create(&self, name: &str, value: &Value) -> TestResponse {
        self.server
            .post(&format!("/admin/operator/tools/{name}/from-definition"))
            .add_header("authorization", &self.token)
            .json(value)
            .await
    }
}
fn operator(dir: &std::path::Path) -> (Arc<OperatorAuthenticator>, String) {
    let token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let hash = argon2_helper::hash(&secrecy::SecretString::from(
        token.secret.expose().to_owned(),
    ))
    .unwrap();
    let file = dir.join("operators.yaml");
    std::fs::write(
        &file,
        format!(
            "operators:\n  - name: fixture\n    public_id: {}\n    token_hash: {}\n",
            token.public_id.as_str(),
            hash
        ),
    )
    .unwrap();
    (
        Arc::new(OperatorAuthenticator::load(&file).unwrap()),
        format!("Bearer {}", token.wire_format()),
    )
}
fn state(
    pool: &sqlx::SqlitePool,
    operator_auth: Arc<OperatorAuthenticator>,
    repo: Arc<RegistrationRepository>,
) -> UdsState {
    let agents = AgentRepository::new(pool.clone());
    let config = config();
    UdsState {
        broker_health: Default::default(),
        admin: Arc::new(AdminService::new(
            agents.clone(),
            BootstrapTokenRepository::new(pool.clone()),
            config,
        )),
        agent_auth: Arc::new(BearerAuthenticator::new(agents).unwrap()),
        operator_auth,
        operator_mtls: None,
        registrations: Some(repo),
        catalog: None,
        resolved_creds: None,
        oauth: None,
        agent_creds: Some(agent_locksmith::repo::AgentCredentialRepository::new(
            pool.clone(),
        )),
        credential_sealing_key: Some(CredentialSealingKey::generate().unwrap()),
        credential_secrets: Some(CredentialSecretsRepository::new(pool.clone())),
        operational_log: None,
        operational_log_store: None,
        op_resolver: None,
    }
}
pub fn path(value: &Value) -> String {
    format!(
        "/admin/operator/integration-definitions/{}/revisions/{}",
        value["id"].as_str().unwrap(),
        value["revision"]
    )
}
pub fn definition() -> Value {
    json!({"schema_version":1,"id":"local.customer","revision":1,"name":"Customer fixture",
        "summary":"Descriptive fixture only", "protocol_profiles":["mcp_streamable_http"],
        "auth_profiles":[{"id":"none","mechanism":"none","setup":"Explicit None after later approval","required_scopes":[]}],
        "workflows":[{"id":"read","summary":"Read a fixture record","operations":["read_record"],"effect":"read"}],
        "setup":"Author a disabled connection; no provider call", "limits":["No live verification"],
        "verification":{"level":"candidate","evidence_ref":"local fixture draft","verified_at":null,"source_revision":null}})
}
pub fn instance() -> Value {
    json!({"definition":{"id":"local.customer","revision":1},"auth_profile_id":"none","upstream":"https://example.com/mcp"})
}

fn config() -> Arc<ArcSwap<agent_locksmith::config::AppConfig>> {
    Arc::new(ArcSwap::from_pointee(
        parse_config_str("listen:\n  port: 9200\ntools: []").unwrap(),
    ))
}
