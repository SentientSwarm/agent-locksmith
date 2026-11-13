//! Shared harness for brokered-routes phase 3 (broker backends) tests:
//! one SQLite substrate behind both the admin router (with the credential
//! sealing key, so broker keys can be sealed) and the agent router.
#![allow(dead_code)]

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::app::build_app_full_with_native;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::broker_health::{BrokerHealth, Prober};
use agent_locksmith::registrations::{Catalog, RegistrationRepository};
use agent_locksmith::repo::{
    AgentCredentialRepository, AgentRepository, BootstrapTokenRepository,
    CredentialSecretsRepository,
};
use agent_locksmith::secret::CredentialSealingKey;
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum::http::Method;
use axum_test::{TestRequest, TestResponse, TestServer};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;

pub struct H {
    _dir: TempDir,
    pub pool: sqlx::SqlitePool,
    pub health: BrokerHealth,
    pub prober: Prober,
    pub admin: TestServer,
    pub agent: TestServer,
    pub op: String,
    pub agent_bearer: String,
    pub pid: String,
}

pub async fn setup() -> H {
    let dir = TempDir::new().unwrap();
    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_token.secret.expose().to_string(),
    ))
    .unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{hash}\"\n",
            op_token.public_id.as_str()
        ),
    )
    .unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = agent_locksmith::repo::audit::AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let bindings = AgentCredentialRepository::new(pool.clone());
    let secrets = CredentialSecretsRepository::new(pool.clone());
    let key = CredentialSealingKey::generate().unwrap();
    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog = Arc::new(ArcSwap::from_pointee(catalog));
    let resolved = Arc::new(ArcSwap::from_pointee(Default::default()));
    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\ntools: []\n").unwrap();
    let cfg = Arc::new(ArcSwap::from_pointee(cfg));
    let (pid, secret) = agents
        .create("agent-1", None, None, None, None, None)
        .await
        .unwrap();
    let bearer =
        Arc::new(BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap());
    let bearer_dyn: Arc<dyn AgentAuthenticator> = bearer.clone();
    let health = BrokerHealth::default();
    let uds = UdsState {
        broker_health: health.clone(),
        admin: Arc::new(AdminService::with_audit(
            agents,
            BootstrapTokenRepository::new(pool.clone()),
            cfg.clone(),
            Some(audit.clone()),
        )),
        agent_auth: bearer,
        operator_auth: Arc::new(OperatorAuthenticator::load(&ops_path).unwrap()),
        operator_mtls: None,
        registrations: Some(registrations.clone()),
        catalog: Some(catalog.clone()),
        resolved_creds: Some(resolved.clone()),
        oauth: None,
        agent_creds: Some(bindings.clone()),
        credential_sealing_key: Some(key.clone()),
        credential_secrets: Some(secrets.clone()),
        operational_log: None,
        operational_log_store: None,
        op_resolver: None,
    };
    let oplog = agent_locksmith::operational_log_sink::OperationalLogEmitter::spawn(
        agent_locksmith::repo::OperationalLogStore::new(pool.clone()),
        64,
    );
    let prober = Prober::new(
        health.clone(),
        catalog.clone(),
        cfg.clone(),
        Some(key.clone()),
        Some(secrets.clone()),
        None,
        Some(Arc::new(oplog)),
    );
    let native = agent_locksmith::native::Runtime::new(
        cfg.load().mcp.clone(),
        Some(registrations.clone()),
        catalog.clone(),
    );
    let agent = build_app_full_with_native(
        cfg,
        Some(audit),
        resolved,
        None,
        Some(bearer_dyn),
        Some(registrations),
        catalog,
        None,
        Some(bindings),
        Some(key),
        Some(secrets),
        None,
        None,
        native,
        health.clone(),
    );
    H {
        _dir: dir,
        pool,
        health,
        prober,
        admin: TestServer::new(build_router(uds)),
        agent: TestServer::new(agent),
        op: format!("Bearer {}", op_token.wire_format()),
        agent_bearer: format!("Bearer lk_{pid}.{}", secret.expose_secret()),
        pid,
    }
}

/// A broker model route body. The key reference is a placeholder until
/// [`H::seal`] replaces it with a sealed value.
pub fn broker_body(upstream: &str, broker: Value) -> Value {
    json!({
        "upstream": upstream,
        "auth": { "kind": "stored_bearer", "secret_ref": "cs_pending" },
        "egress": "direct",
        "broker": broker,
    })
}

pub fn upstream_body(upstream: &str) -> Value {
    json!({ "upstream": upstream, "auth": { "kind": "none" }, "egress": "direct" })
}

impl H {
    pub fn op_req(&self, m: Method, path: &str) -> TestRequest {
        self.admin
            .method(m, &format!("/admin/operator{path}"))
            .add_header("authorization", &self.op)
    }

    pub async fn put_model(&self, name: &str, body: Value) -> TestResponse {
        self.op_req(Method::PUT, &format!("/models/{name}"))
            .json(&body)
            .await
    }

    /// Seal `value` as the route's own key (the broker key on a broker).
    pub async fn seal(&self, name: &str, value: &str) -> String {
        let r = self
            .op_req(Method::PUT, &format!("/models/{name}/credential"))
            .json(&json!({ "value": value }))
            .await;
        r.assert_status_ok();
        r.json::<Value>()["secret_ref"]
            .as_str()
            .unwrap()
            .to_string()
    }

    pub async fn grant(&self, names: &[&str]) {
        self.op_req(Method::PATCH, &format!("/agents/{}", self.pid))
            .json(&json!({ "allowlist": names }))
            .await
            .assert_status_no_content();
    }

    pub async fn bind(&self, name: &str, spec: Value) -> TestResponse {
        self.op_req(
            Method::PUT,
            &format!("/agents/{}/credentials/{name}", self.pid),
        )
        .json(&json!({ "auth_spec": spec }))
        .await
    }

    pub async fn call(&self, name: &str, path: &str) -> TestResponse {
        self.agent
            .get(&format!("/api/{name}{path}"))
            .add_header("authorization", &self.agent_bearer)
            .await
    }

    pub async fn last_audit(&self, event: &str) -> Value {
        let details: String = sqlx::query_scalar(
            "SELECT details FROM audit WHERE event = ? ORDER BY id DESC LIMIT 1",
        )
        .bind(event)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        serde_json::from_str(&details).unwrap()
    }
}
