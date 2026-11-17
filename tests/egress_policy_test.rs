//! AGENT-137 — Locksmith publishes the egress policy Pipelock enforces.
//!
//! `GET /admin/operator/egress/policy` lists every host an enabled
//! `proxied` route reaches, with the routes behind it, so the proxy's
//! allowlist is derived from Locksmith instead of maintained beside it.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::egress_policy::pipelock_allowlist;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::auth_v2::{BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{Catalog, RegistrationRepository};
use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository, BootstrapTokenRepository};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;

struct H {
    _dir: TempDir,
    pool: sqlx::SqlitePool,
    admin: TestServer,
    op: String,
}

async fn setup() -> H {
    setup_with_tools("tools: []\n").await
}

/// `tools` is the YAML `tools:` block of the daemon config.
async fn setup_with_tools(tools: &str) -> H {
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
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let cfg = parse_config_str(&format!(
        "listen:\n  host: 127.0.0.1\n  port: 9200\negress_proxy: \"http://127.0.0.1:8888\"\n{tools}"
    ))
    .unwrap();
    let cfg = Arc::new(ArcSwap::from_pointee(cfg));
    let uds = UdsState {
        broker_health: Default::default(),
        admin: Arc::new(AdminService::new(
            agents.clone(),
            BootstrapTokenRepository::new(pool.clone()),
            cfg,
        )),
        agent_auth: Arc::new(BearerAuthenticator::with_audit(agents, None).unwrap()),
        operator_auth: Arc::new(OperatorAuthenticator::load(&ops_path).unwrap()),
        operator_mtls: None,
        registrations: Some(registrations),
        catalog: Some(Arc::new(ArcSwap::from_pointee(catalog))),
        resolved_creds: Some(Arc::new(ArcSwap::from_pointee(Default::default()))),
        oauth: None,
        agent_creds: Some(AgentCredentialRepository::new(pool.clone())),
        credential_sealing_key: None,
        credential_secrets: None,
        operational_log: None,
        operational_log_store: None,
        op_resolver: None,
    };
    H {
        _dir: dir,
        pool: pool.clone(),
        admin: TestServer::new(build_router(uds)),
        op: format!("Bearer {}", op_token.wire_format()),
    }
}

impl H {
    async fn route(&self, name: &str, upstream: &str, egress: &str) {
        self.admin
            .put(&format!("/admin/operator/tools/{name}"))
            .add_header("authorization", &self.op)
            .json(&json!({ "upstream": upstream, "auth": { "kind": "none" }, "egress": egress }))
            .await
            .assert_status_ok();
    }

    async fn policy(&self) -> Value {
        let r = self
            .admin
            .get("/admin/operator/egress/policy")
            .add_header("authorization", &self.op)
            .await;
        r.assert_status_ok();
        r.json()
    }
}

#[tokio::test]
async fn policy_groups_proxied_routes_by_host() {
    let h = setup().await;
    h.route("search", "https://api.search.example/v1", "proxied")
        .await;
    h.route("search-b", "https://api.search.example/v2", "proxied")
        .await;
    h.route("docs", "https://docs.example:8443", "proxied")
        .await;
    h.route("lan", "http://lan.example:8080", "direct").await;
    let p = h.policy().await;
    assert_eq!(p["mode"], "pipelock");
    assert_eq!(p["egress_proxy_set"], true);
    assert!(
        p.get("egress_proxy").is_none(),
        "the proxy URL is not exposed"
    );
    assert_eq!(
        p["hosts"],
        json!([
            { "host": "api.search.example", "port": 443, "routes": ["search", "search-b"] },
            { "host": "docs.example", "port": 8443, "routes": ["docs"] },
        ])
    );
}

#[tokio::test]
async fn removed_route_is_left_out() {
    let h = setup().await;
    h.route("search", "https://api.search.example", "proxied")
        .await;
    h.admin
        .delete("/admin/operator/tools/search")
        .add_header("authorization", &h.op)
        .await;
    assert_eq!(h.policy().await["hosts"], json!([]));
}

#[tokio::test]
async fn policy_requires_an_operator() {
    let h = setup().await;
    let r = h.admin.get("/admin/operator/egress/policy").await;
    assert_eq!(r.status_code(), 401);
}

#[test]
fn pipelock_render_lists_hosts() {
    let policy = json!({
        "mode": "pipelock",
        "hosts": [
            { "host": "a.example", "port": 443, "routes": ["a"] },
            { "host": "b.example", "port": 8443, "routes": ["b"] },
        ]
    });
    let yaml: serde_yaml::Value = serde_yaml::from_str(&pipelock_allowlist(&policy)).unwrap();
    assert_eq!(
        yaml["api_allowlist"],
        serde_yaml::from_str::<serde_yaml::Value>("[a.example, b.example]").unwrap()
    );
}

#[test]
fn pipelock_render_escapes_hosts() {
    // AGENT-269: rendered with a YAML emitter, not string interpolation,
    // so a host the URL parser allows (an opaque host may hold `"`)
    // can't break or extend the document.
    let odd = "a\"b: c\n- injected";
    let policy = json!({ "hosts": [ { "host": odd, "port": 443, "routes": ["x"] } ] });
    let yaml: serde_yaml::Value = serde_yaml::from_str(&pipelock_allowlist(&policy)).unwrap();
    assert_eq!(yaml["api_allowlist"][0].as_str(), Some(odd));
    assert_eq!(yaml["api_allowlist"].as_sequence().map(Vec::len), Some(1));
}

#[tokio::test]
async fn yaml_tools_are_ignored_when_registrations_are_authoritative() {
    // With a registration repository the database is the authority
    // (D4); a YAML tool the operator never registered is not served, so
    // it must not widen the allowlist.
    let h = setup_with_tools(
        "tools:\n  - name: stale\n    description: d\n    upstream: https://stale.example\n    egress: proxied\n",
    )
    .await;
    assert_eq!(h.policy().await["hosts"], json!([]));
}

#[tokio::test]
async fn registration_read_failure_is_an_error_not_a_partial_policy() {
    let h = setup().await;
    h.route("search", "https://api.search.example", "proxied")
        .await;
    sqlx::query("DROP TABLE registrations")
        .execute(&h.pool)
        .await
        .ok();
    let r = h
        .admin
        .get("/admin/operator/egress/policy")
        .add_header("authorization", &h.op)
        .await;
    assert_eq!(r.status_code(), 503, "{}", r.text());
    assert_eq!(
        r.json::<Value>()["error"]["code"],
        "registrations_unavailable"
    );
}

fn device_code(token_url: &str) -> Value {
    json!({ "kind": "oauth_device_code", "client_id": "c", "scopes": [],
        "device_url": "https://auth.provider.example/device", "token_url": token_url })
}

/// AGENT-269 — a proxied OAuth route's token calls go through the egress
/// proxy too, so the policy lists the hosts they reach: the route's own
/// token URL and any an agent binding selects for it.
#[tokio::test]
async fn policy_lists_the_token_hosts_of_proxied_oauth_routes() {
    let h = setup().await;
    for (name, egress, token) in [
        (
            "codex",
            "proxied",
            "https://auth.provider.example/oauth/token",
        ),
        (
            "lan-oauth",
            "direct",
            "https://auth.lan.example/oauth/token",
        ),
    ] {
        h.admin
            .put(&format!("/admin/operator/models/{name}"))
            .add_header("authorization", &h.op)
            .json(
                &json!({ "upstream": "https://api.provider.example/v1", "egress": egress,
                "auth": device_code(token) }),
            )
            .await
            .assert_status_ok();
    }
    let agents = AgentRepository::new(h.pool.clone());
    agents
        .create("a1", None, None, None, None, None)
        .await
        .unwrap();
    let id = agents.get_by_name("a1").await.unwrap().unwrap().id;
    let bound = serde_json::from_value(device_code("https://alt-auth.example:8443/token")).unwrap();
    AgentCredentialRepository::new(h.pool.clone())
        .set(id, "codex", &bound)
        .await
        .unwrap();
    let lan = serde_json::from_value(device_code("https://alt-lan.example/token")).unwrap();
    AgentCredentialRepository::new(h.pool.clone())
        .set(id, "lan-oauth", &lan)
        .await
        .unwrap();
    assert_eq!(
        h.policy().await["hosts"],
        json!([
            { "host": "alt-auth.example", "port": 8443, "routes": ["codex"] },
            { "host": "api.provider.example", "port": 443, "routes": ["codex"] },
            { "host": "auth.provider.example", "port": 443, "routes": ["codex"] },
        ])
    );
}
