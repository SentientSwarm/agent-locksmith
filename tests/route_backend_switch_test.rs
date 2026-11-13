//! Brokered routes phase 2 — switching a route's active backend.
//!
//! Proves, against a real database and the proxy router:
//!   - a switch keeps grants and swaps bindings with the backend;
//!   - switching back restores the original bindings;
//!   - an agent with no binding on the new backend gets 403
//!     account_binding_missing and nothing is dispatched;
//!   - a plain destination edit after a switch still clears authority and the
//!     guard leaves no residue;
//!   - stale revisions, OAuth backends, native routes and no-op switches are
//!     refused without change.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::app::build_app_full_with_phase_j;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::{EgressMode, parse_config_str};
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::backends::{
    BackendError, BackendRepository, PRIMARY, RouteBackend,
};
use agent_locksmith::registrations::{AuthSpec, Catalog, RegistrationRepository};
use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository, BootstrapTokenRepository};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

struct H {
    _dir: TempDir,
    pool: sqlx::SqlitePool,
    registrations: Arc<RegistrationRepository>,
    catalog: Arc<ArcSwap<Catalog>>,
    admin: TestServer,
    agent: TestServer,
    op: String,
    agent_bearer: String,
    pid: String,
}

async fn setup() -> H {
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
    let uds = UdsState {
        broker_health: Default::default(),
        admin: Arc::new(AdminService::new(
            agents,
            BootstrapTokenRepository::new(pool.clone()),
            cfg.clone(),
        )),
        agent_auth: bearer,
        operator_auth: Arc::new(OperatorAuthenticator::load(&ops_path).unwrap()),
        operator_mtls: None,
        registrations: Some(registrations.clone()),
        catalog: Some(catalog.clone()),
        resolved_creds: Some(resolved.clone()),
        oauth: None,
        agent_creds: Some(bindings.clone()),
        credential_sealing_key: None,
        credential_secrets: None,
        operational_log: None,
        operational_log_store: None,
        op_resolver: None,
    };
    let registrations_keep = registrations.clone();
    let catalog_keep = catalog.clone();
    let agent = build_app_full_with_phase_j(
        cfg,
        Some(audit),
        resolved,
        None,
        Some(bearer_dyn),
        Some(registrations),
        catalog,
        None,
        Some(bindings),
        None,
        None,
    );
    H {
        _dir: dir,
        pool: pool.clone(),
        registrations: registrations_keep,
        catalog: catalog_keep,
        admin: TestServer::new(build_router(uds)),
        agent: TestServer::new(agent),
        op: format!("Bearer {}", op_token.wire_format()),
        agent_bearer: format!("Bearer lk_{pid}.{}", secret.expose_secret()),
        pid,
    }
}

impl H {
    async fn put_route(&self, name: &str, body: Value) -> axum_test::TestResponse {
        self.admin
            .put(&format!("/admin/operator/models/{name}"))
            .add_header("authorization", &self.op)
            .json(&body)
            .await
    }

    /// Grant `names` and bind each to explicit no-auth.
    async fn grant(&self, names: &[&str]) {
        self.admin
            .patch(&format!("/admin/operator/agents/{}", self.pid))
            .add_header("authorization", &self.op)
            .json(&json!({ "allowlist": names }))
            .await
            .assert_status_no_content();
        for name in names {
            self.admin
                .put(&format!(
                    "/admin/operator/agents/{}/credentials/{name}",
                    self.pid
                ))
                .add_header("authorization", &self.op)
                .json(&json!({ "auth_spec": { "kind": "none" } }))
                .await
                .assert_status_ok();
        }
    }
}

fn route_body(upstream: &str) -> Value {
    json!({ "upstream": upstream, "auth": { "kind": "none" }, "egress": "direct" })
}

async fn upstream() -> MockServer {
    let m = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&m)
        .await;
    m
}

fn backend(name: &str, upstream: &str) -> RouteBackend {
    RouteBackend {
        route: "r".into(),
        name: name.into(),
        upstream: upstream.into(),
        egress: EgressMode::Direct,
        upstream_ca_pem: None,
        auth: AuthSpec::None,
        broker: None,
        created_at: 0,
        updated_at: 0,
    }
}

impl H {
    fn backends(&self) -> BackendRepository {
        BackendRepository::new(self.pool.clone())
    }

    async fn revision(&self) -> i64 {
        sqlx::query_scalar("SELECT revision FROM registration_instances WHERE name = 'r'")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn switch(
        &self,
        target: &str,
    ) -> Result<agent_locksmith::registrations::backends::SwitchOutcome, BackendError> {
        let rev = self.revision().await;
        let out = self.backends().switch("r", target, rev).await;
        self.catalog.store(Arc::new(
            Catalog::from_repo(self.registrations.as_ref())
                .await
                .unwrap(),
        ));
        out
    }

    async fn count(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(&self.pool).await.unwrap()
    }

    async fn granted(&self) -> bool {
        self.count(
            "SELECT COUNT(*) FROM agents, json_each(agents.tool_allowlist) WHERE value = 'r'",
        )
        .await
            == 1
    }

    async fn bound(&self) -> bool {
        self.count("SELECT COUNT(*) FROM agent_credential_overrides WHERE registration = 'r'")
            .await
            == 1
    }

    async fn upstream_of_route(&self) -> String {
        sqlx::query_scalar("SELECT upstream FROM registrations WHERE name = 'r'")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn call(&self) -> axum_test::TestResponse {
        self.agent
            .get("/api/r/ping")
            .add_header("authorization", &self.agent_bearer)
            .await
    }
}

/// Route `r` on `a`, a granted+bound agent, and a declared backend `b`.
async fn scenario() -> (H, MockServer, MockServer) {
    let h = setup().await;
    let (a, b) = (upstream().await, upstream().await);
    h.put_route("r", route_body(&a.uri()))
        .await
        .assert_status_ok();
    h.grant(&["r"]).await;
    h.backends().put(&backend("b", &b.uri())).await.unwrap();
    (h, a, b)
}

#[tokio::test]
async fn switch_keeps_grants_and_swaps_bindings() {
    let (h, a, b) = scenario().await;
    let out = h.switch("b").await.unwrap();
    assert_eq!((out.from.as_str(), out.to.as_str()), (PRIMARY, "b"));
    assert_eq!((out.bindings_stashed, out.bindings_restored), (1, 0));
    assert!(h.granted().await, "grant survives the switch");
    assert!(!h.bound().await, "the binding stays with the old backend");
    assert_eq!(h.upstream_of_route().await, b.uri());
    assert_eq!(h.backends().active_backend("r").await.unwrap(), "b");
    let primary = h.backends().get("r", PRIMARY).await.unwrap().unwrap();
    assert_eq!(
        primary.upstream,
        a.uri(),
        "old destination recorded as a backend"
    );
    assert_eq!(
        h.count("SELECT COUNT(*) FROM backend_bindings WHERE backend = 'primary'")
            .await,
        1
    );
    assert_eq!(h.count("SELECT COUNT(*) FROM route_switch_guard").await, 0);
}

#[tokio::test]
async fn switch_round_trip_restores_bindings() {
    let (h, a, _b) = scenario().await;
    h.switch("b").await.unwrap();
    h.grant(&["r"]).await; // bind on b
    let out = h.switch(PRIMARY).await.unwrap();
    assert_eq!((out.bindings_stashed, out.bindings_restored), (1, 1));
    assert!(h.granted().await && h.bound().await);
    assert_eq!(h.upstream_of_route().await, a.uri());
    assert_eq!(
        h.count("SELECT COUNT(*) FROM backend_bindings WHERE backend = 'b'")
            .await,
        1,
        "b's binding is stashed for the next switch"
    );
    h.call().await.assert_status_ok();
    assert_eq!(a.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn agent_without_binding_on_new_backend_gets_account_binding_missing() {
    let (h, a, b) = scenario().await;
    h.call().await.assert_status_ok();
    h.switch("b").await.unwrap();
    let resp = h.call().await;
    assert_eq!(resp.status_code(), 403);
    // Wire code is tool_not_allowed; the audit reason says which check failed.
    assert_eq!(resp.json::<Value>()["error"]["code"], "tool_not_allowed");
    let reason: String = sqlx::query_scalar(
        "SELECT json_extract(details, '$.reason') FROM audit \
         WHERE event = 'authz_denied' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(reason, "account_binding_missing");
    assert!(
        b.received_requests().await.unwrap().is_empty(),
        "nothing dispatched"
    );
    assert_eq!(a.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn plain_edit_after_switch_still_clears_authority() {
    let (h, _a, _b) = scenario().await;
    h.switch("b").await.unwrap();
    h.grant(&["r"]).await;
    assert_eq!(h.count("SELECT COUNT(*) FROM route_switch_guard").await, 0);
    h.put_route("r", route_body("https://moved.example"))
        .await
        .assert_status_ok();
    assert!(!h.granted().await, "0009 still revokes the grant");
    assert!(!h.bound().await, "0009 still clears the binding");
}

#[tokio::test]
async fn stale_revision_refuses_without_change() {
    let (h, a, _b) = scenario().await;
    let rev = h.revision().await;
    let err = h.backends().switch("r", "b", rev - 1).await.unwrap_err();
    assert!(matches!(err, BackendError::RevisionConflict), "{err:?}");
    assert_eq!(h.upstream_of_route().await, a.uri());
    assert!(h.granted().await && h.bound().await);
    assert_eq!(h.count("SELECT COUNT(*) FROM backend_bindings").await, 0);
    assert_eq!(h.revision().await, rev);
}

#[tokio::test]
async fn oauth_backend_switch_refused() {
    let (h, a, _b) = scenario().await;
    let mut o = backend("oauth", "https://o.example");
    o.auth = AuthSpec::OauthDeviceCode {
        client_id: "c".into(),
        scopes: vec![],
        device_url: "https://o.example/device".into(),
        token_url: "https://o.example/token".into(),
        session_label: None,
    };
    h.backends().put(&o).await.unwrap();
    let err = h.switch("oauth").await.unwrap_err();
    assert!(matches!(err, BackendError::AuthUnsupported), "{err:?}");
    assert_eq!(h.upstream_of_route().await, a.uri());
    assert!(h.bound().await);
}

#[tokio::test]
async fn native_or_pinned_route_refused() {
    let (h, _a, _b) = scenario().await;
    sqlx::query(
        "UPDATE registrations SET kind = 'tool', protocol = 'mcp_streamable_http', \
         mcp_json = '{\"protocol_version\":\"2025-11-25\"}' WHERE name = 'r'",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let err = h.switch("b").await.unwrap_err();
    assert!(matches!(err, BackendError::RouteNotSwitchable), "{err:?}");
}

#[tokio::test]
async fn switch_to_active_backend_refused() {
    let (h, _a, _b) = scenario().await;
    let err = h.switch(PRIMARY).await.unwrap_err();
    assert!(matches!(err, BackendError::ActiveBackend), "{err:?}");
    let err = h.switch("nope").await.unwrap_err();
    assert!(matches!(err, BackendError::NotFound), "{err:?}");
}
