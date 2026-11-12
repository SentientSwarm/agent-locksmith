//! Brokered routes phase 2 — route backend admin API.
//!
//! Proves over the admin router: backend CRUD, the If-Match requirement,
//! the switch response (profile before/after), the security audit row, the
//! credential sweeper keeping stashed references, and that the proxy uses
//! the new backend immediately after a switch.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::app::build_app_full_with_phase_j;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{Catalog, RegistrationRepository};
use agent_locksmith::repo::{
    AgentCredentialRepository, AgentRepository, BootstrapTokenRepository,
    CredentialSecretsRepository,
};
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
        pool: pool.clone(),
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

fn backend_body(upstream: &str) -> Value {
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

impl H {
    fn op_req(&self, m: axum::http::Method, path: &str) -> axum_test::TestRequest {
        self.admin
            .method(m, &format!("/admin/operator{path}"))
            .add_header("authorization", &self.op)
    }

    async fn revision(&self) -> i64 {
        self.op_req(axum::http::Method::GET, "/routes/r/backends")
            .await
            .json::<Value>()["revision"]
            .as_i64()
            .unwrap()
    }

    async fn switch(&self, to: &str) -> axum_test::TestResponse {
        let rev = self.revision().await;
        self.op_req(axum::http::Method::POST, "/routes/r/switch")
            .add_header("if-match", &rev.to_string())
            .json(&json!({ "backend": to }))
            .await
    }
}

#[tokio::test]
async fn put_list_get_delete_backend_over_admin_api() {
    let h = setup().await;
    h.put_route("r", route_body("https://a.example"))
        .await
        .assert_status_ok();
    use axum::http::Method;
    h.op_req(Method::PUT, "/routes/r/backends/broker")
        .json(&backend_body("https://b.example"))
        .await
        .assert_status_ok();
    let list: Value = h.op_req(Method::GET, "/routes/r/backends").await.json();
    assert_eq!(list["active_backend"], "primary");
    assert_eq!(list["backends"][0]["name"], "broker");
    assert_eq!(list["backends"][0]["upstream"], "https://b.example");
    let one: Value = h
        .op_req(Method::GET, "/routes/r/backends/broker")
        .await
        .json();
    assert_eq!(one["upstream"], "https://b.example");
    // The active backend cannot be replaced or deleted through this API.
    let r = h
        .op_req(Method::PUT, "/routes/r/backends/primary")
        .json(&backend_body("https://x.example"))
        .await;
    assert_eq!(r.status_code(), 409);
    assert_eq!(r.json::<Value>()["error"]["code"], "active_backend");
    // OAuth backends are refused in phase 2.
    let r = h
        .op_req(Method::PUT, "/routes/r/backends/o")
        .json(
            &json!({ "upstream": "https://o.example", "egress": "direct", "auth": {
            "kind": "oauth_device_code", "client_id": "c", "scopes": [],
            "device_url": "https://o.example/d", "token_url": "https://o.example/t" } }),
        )
        .await;
    assert_eq!(
        r.json::<Value>()["error"]["code"],
        "backend_auth_unsupported"
    );
    h.op_req(Method::DELETE, "/routes/r/backends/broker")
        .await
        .assert_status_no_content();
    assert_eq!(
        h.op_req(Method::GET, "/routes/r/backends/broker")
            .await
            .status_code(),
        404
    );
}

#[tokio::test]
async fn switch_requires_if_match_428() {
    let h = setup().await;
    h.put_route("r", route_body("https://a.example"))
        .await
        .assert_status_ok();
    h.op_req(axum::http::Method::PUT, "/routes/r/backends/b")
        .json(&backend_body("https://b.example"))
        .await
        .assert_status_ok();
    let r = h
        .op_req(axum::http::Method::POST, "/routes/r/switch")
        .json(&json!({ "backend": "b" }))
        .await;
    assert_eq!(r.status_code(), 428);
    assert_eq!(r.json::<Value>()["error"]["code"], "if_match_required");
    let r = h
        .op_req(axum::http::Method::POST, "/routes/r/switch")
        .add_header("if-match", "999")
        .json(&json!({ "backend": "b" }))
        .await;
    assert_eq!(r.status_code(), 409);
    assert_eq!(r.json::<Value>()["error"]["code"], "revision_conflict");
}

#[tokio::test]
async fn switch_reports_profile_change() {
    let h = setup().await;
    let codex = upstream().await;
    h.put_route(
        "r",
        route_body(&format!("{}/backend-api/codex", codex.uri())),
    )
    .await
    .assert_status_ok();
    h.op_req(axum::http::Method::PUT, "/routes/r/backends/plain")
        .json(&backend_body("https://plain.example"))
        .await
        .assert_status_ok();
    let r = h.switch("plain").await;
    r.assert_status_ok();
    let out: Value = r.json();
    assert_eq!(out["from"], "primary");
    assert_eq!(out["to"], "plain");
    assert_eq!(out["profile_before"], "openai-codex-responses");
    assert_eq!(out["profile_after"], "generic");
    assert!(out["revision"].as_i64().unwrap() > 1);
}

#[tokio::test]
async fn switch_writes_security_audit_without_secrets() {
    let h = setup().await;
    h.put_route("r", route_body("https://a.example"))
        .await
        .assert_status_ok();
    h.grant(&["r"]).await;
    h.op_req(axum::http::Method::PUT, "/routes/r/backends/b")
        .json(&backend_body("https://b.example"))
        .await
        .assert_status_ok();
    h.switch("b").await.assert_status_ok();
    let (class, op, tool, details): (String, String, String, String) = sqlx::query_as(
        "SELECT event_class, operator_name, tool, details FROM audit \
         WHERE event = 'route_backend_switched'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(
        (class.as_str(), op.as_str(), tool.as_str()),
        ("security", "alice", "r")
    );
    let d: Value = serde_json::from_str(&details).unwrap();
    assert_eq!(d["from"], "primary");
    assert_eq!(d["to"], "b");
    assert_eq!(d["bindings_stashed"], 1);
    assert!(!details.contains("auth_spec") && !details.contains("secret_ref"));
}

#[tokio::test]
async fn sweeper_keeps_stashed_secret_refs() {
    let h = setup().await;
    let secrets = CredentialSecretsRepository::new(h.pool.clone());
    let stashed = secrets.insert(b"sealed-a", b"nonce-a-0000").await.unwrap();
    let template = secrets.insert(b"sealed-b", b"nonce-b-0000").await.unwrap();
    let orphan = secrets.insert(b"sealed-c", b"nonce-c-0000").await.unwrap();
    h.put_route("r", route_body("https://a.example"))
        .await
        .assert_status_ok();
    h.grant(&["r"]).await;
    // Stash a stored-bearer binding and declare a backend whose template
    // references the second value.
    sqlx::query(
        "INSERT INTO registration_backends (route, name, upstream, egress, auth_json, created_at, updated_at) \
         VALUES ('r', 'b', 'https://b.example', 'direct', ?, 1, 1)",
    )
    .bind(json!({ "kind": "stored_bearer", "secret_ref": template }).to_string())
    .execute(&h.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO backend_bindings (agent_id, route, backend, auth_spec, created_at, updated_at) \
         SELECT id, 'r', 'b', ?, 1, 1 FROM agents",
    )
    .bind(json!({ "kind": "stored_bearer", "secret_ref": stashed }).to_string())
    .execute(&h.pool)
    .await
    .unwrap();
    let tombstoned = secrets.tombstone_unreferenced(i64::MAX).await.unwrap();
    assert_eq!(tombstoned, 1, "only the unreferenced value is tombstoned");
    for (r, live) in [(&stashed, true), (&template, true), (&orphan, false)] {
        let tomb: Option<i64> =
            sqlx::query_scalar("SELECT tombstoned_at FROM credential_secrets WHERE secret_ref = ?")
                .bind(r)
                .fetch_one(&h.pool)
                .await
                .unwrap();
        assert_eq!(tomb.is_none(), live, "{r}");
    }
}

#[tokio::test]
async fn proxy_uses_new_backend_immediately_after_switch() {
    let h = setup().await;
    let (a, b) = (upstream().await, upstream().await);
    h.put_route("r", route_body(&a.uri()))
        .await
        .assert_status_ok();
    h.grant(&["r"]).await;
    h.op_req(axum::http::Method::PUT, "/routes/r/backends/b")
        .json(&backend_body(&b.uri()))
        .await
        .assert_status_ok();
    h.switch("b").await.assert_status_ok();
    h.grant(&["r"]).await; // bind on b
    h.agent
        .get("/api/r/ping")
        .add_header("authorization", &h.agent_bearer)
        .await
        .assert_status_ok();
    assert_eq!(b.received_requests().await.unwrap().len(), 1);
    assert!(a.received_requests().await.unwrap().is_empty());
}
