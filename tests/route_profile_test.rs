//! Brokered routes phase 1 — route request profiles.
//!
//! Proves through the admin API and proxy router:
//!   - a route without a profile infers it from the upstream, and the admin
//!     read says so (`profile_source: inferred`);
//!   - an explicit profile is stored, reported, and a later PUT without it
//!     reverts to inference;
//!   - an unknown profile is refused before anything is written;
//!   - a profile change keeps grants and bindings (behaviour, not destination);
//!   - Codex wire behaviour follows the effective profile, not the URL.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::app::build_app_full_with_phase_j;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{Catalog, RegistrationRepository};
use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository, BootstrapTokenRepository};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "support/registered_legacy.rs"]
mod registered;

struct H {
    _dir: TempDir,
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

fn http_route(upstream: &str, profile: Option<&str>) -> Value {
    let mut body = json!({
        "upstream": upstream,
        "auth": { "kind": "none" },
        "egress": "direct",
    });
    if let Some(p) = profile {
        body["profile"] = json!(p);
    }
    body
}

impl H {
    async fn read(&self, name: &str) -> Value {
        self.admin
            .get(&format!("/admin/operator/models/{name}"))
            .add_header("authorization", &self.op)
            .await
            .json()
    }
}

#[tokio::test]
async fn put_without_profile_infers_and_reports_source() {
    let h = setup().await;
    h.put_route(
        "cx",
        http_route("http://127.0.0.1:1/backend-api/codex", None),
    )
    .await
    .assert_status_ok();
    h.put_route("plain", http_route("http://127.0.0.1:1/v1", None))
        .await
        .assert_status_ok();
    let cx = h.read("cx").await;
    assert_eq!(cx["profile"], "openai-codex-responses");
    assert_eq!(cx["profile_source"], "inferred");
    let plain = h.read("plain").await;
    assert_eq!(plain["profile"], "generic");
    assert_eq!(plain["profile_source"], "inferred");
}

#[tokio::test]
async fn explicit_profile_is_stored_and_reput_without_it_reverts_to_inferred() {
    let h = setup().await;
    let codex = "http://127.0.0.1:1/backend-api/codex";
    h.put_route("cx", http_route(codex, Some("generic")))
        .await
        .assert_status_ok();
    let cx = h.read("cx").await;
    assert_eq!(cx["profile"], "generic");
    assert_eq!(cx["profile_source"], "explicit");
    h.put_route("cx", http_route(codex, None))
        .await
        .assert_status_ok();
    let cx = h.read("cx").await;
    assert_eq!(cx["profile"], "openai-codex-responses");
    assert_eq!(cx["profile_source"], "inferred");
}

#[tokio::test]
async fn unknown_profile_is_400_invalid_profile_and_writes_nothing() {
    let h = setup().await;
    let resp = h
        .put_route(
            "bad",
            http_route("http://127.0.0.1:1/v1", Some("anthropic-messages")),
        )
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());
    assert_eq!(resp.json::<Value>()["error"]["code"], "invalid_profile");
    let missing = h
        .admin
        .get("/admin/operator/models/bad")
        .add_header("authorization", &h.op)
        .await;
    assert_eq!(missing.status_code(), 404);
}

#[tokio::test]
async fn profile_change_keeps_grants_and_bindings() {
    let h = setup().await;
    let codex = "http://127.0.0.1:1/backend-api/codex";
    h.put_route("cx", http_route(codex, None))
        .await
        .assert_status_ok();
    h.grant(&["cx"]).await;
    h.put_route("cx", http_route(codex, Some("generic")))
        .await
        .assert_status_ok();
    let agent: Value = h
        .admin
        .get(&format!("/admin/operator/agents/{}", h.pid))
        .add_header("authorization", &h.op)
        .await
        .json();
    assert!(agent.to_string().contains("\"cx\""), "{agent}");
    let creds: Value = h
        .admin
        .get(&format!("/admin/operator/agents/{}/credentials", h.pid))
        .add_header("authorization", &h.op)
        .await
        .json();
    assert!(creds.to_string().contains("\"cx\""), "{creds}");
}

async fn responses_upstream(at: &str) -> MockServer {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{at}/responses")))
        .respond_with(ResponseTemplate::new(200).set_body_string("data: {}\n\n"))
        .mount(&mock)
        .await;
    mock
}

fn codex_like_body() -> Value {
    json!({"model": "m", "input": [], "store": true, "stream": false, "max_output_tokens": 9})
}

async fn last_request(mock: &MockServer) -> wiremock::Request {
    mock.received_requests()
        .await
        .unwrap()
        .pop()
        .expect("upstream saw a request")
}

impl H {
    async fn post_responses(&self, name: &str) -> axum_test::TestResponse {
        self.agent
            .post(&format!("/api/{name}/responses"))
            .add_header("authorization", &self.agent_bearer)
            .add_header("openai-beta", "agent-chosen")
            .json(&codex_like_body())
            .await
    }
}

#[tokio::test]
async fn explicit_codex_profile_applies_fixups_on_a_non_codex_upstream() {
    let mock = responses_upstream("/router").await;
    let h = setup().await;
    h.put_route(
        "brk",
        http_route(
            &format!("{}/router", mock.uri()),
            Some("openai-codex-responses"),
        ),
    )
    .await
    .assert_status_ok();
    h.grant(&["brk"]).await;
    h.post_responses("brk").await.assert_status_ok();
    let req = last_request(&mock).await;
    let sent: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(sent["store"], false);
    assert_eq!(sent["stream"], true);
    assert!(sent["instructions"].is_string());
    assert!(sent.get("max_output_tokens").is_none());
    assert_eq!(
        req.headers.get("openai-beta").unwrap(),
        "responses=experimental"
    );
    assert_eq!(req.headers.get("originator").unwrap(), "agent-1");
}

#[tokio::test]
async fn explicit_generic_profile_disables_fixups_on_codex_upstream() {
    let mock = responses_upstream("/backend-api/codex").await;
    let h = setup().await;
    h.put_route(
        "cxg",
        http_route(
            &format!("{}/backend-api/codex", mock.uri()),
            Some("generic"),
        ),
    )
    .await
    .assert_status_ok();
    h.grant(&["cxg"]).await;
    h.post_responses("cxg").await.assert_status_ok();
    let req = last_request(&mock).await;
    let sent: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(sent, codex_like_body());
    assert_eq!(req.headers.get("openai-beta").unwrap(), "agent-chosen");
    assert!(req.headers.get("originator").is_none());
}

#[tokio::test]
async fn legacy_config_tool_on_codex_upstream_still_gets_fixups() {
    let mock = responses_upstream("/backend-api/codex").await;
    let yaml = format!(
        "listen:\n  host: \"127.0.0.1\"\n  port: 9200\ntools:\n  - name: \"cx\"\n    \
         description: \"codex\"\n    upstream: \"{}/backend-api/codex\"\n    \
         auth:\n      header: \"Authorization\"\n      value: \"Bearer t\"\n    \
         timeout_seconds: 30\n",
        mock.uri()
    );
    let mut lh = registered::setup(parse_config_str(&yaml).unwrap()).await;
    lh.server.add_header("authorization", &lh.bearer);
    lh.server
        .post("/api/cx/responses")
        .json(&codex_like_body())
        .await
        .assert_status_ok();
    let sent: Value = serde_json::from_slice(&last_request(&mock).await.body).unwrap();
    assert_eq!(sent["store"], false);
    assert!(sent.get("max_output_tokens").is_none());
}
