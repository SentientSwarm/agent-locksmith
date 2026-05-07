//! T6.8 — bootstrap-only listener exposes ONLY register, in-process.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::bootstrap_listener::{BootstrapState, build_router};
use agent_locksmith::admin::service::MintBootstrapInput;
use agent_locksmith::auth_v2::OperatorIdentity;
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::audit::AuditRepository;
use agent_locksmith::repo::{AgentRepository, BootstrapTokenRepository};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;

async fn build_admin() -> (TempDir, AdminService) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool.clone());
    let audit = AuditRepository::new(pool);
    let cfg = parse_config_str(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#,
    )
    .unwrap();
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let admin = AdminService::with_audit(agents, bootstrap, config, Some(audit));
    (dir, admin)
}

#[tokio::test]
async fn register_via_bootstrap_token_succeeds() {
    let (_dir, admin) = build_admin().await;
    let op = OperatorIdentity {
        name: "alice".into(),
        scope: None,
        auth_method: None,
    };
    let minted = admin
        .mint_bootstrap_token(
            &op,
            MintBootstrapInput {
                tool_allowlist: None,
                expires_at: None,
                single_use: true,
            },
        )
        .await
        .unwrap();

    let state = BootstrapState {
        admin: Arc::new(admin),
    };
    let app = build_router(state);
    let server = TestServer::new(app);
    let resp = server
        .post("/admin/agent/register")
        .json(&json!({"bootstrap_token": minted.token, "name": "bs-agent"}))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["token"].as_str().unwrap().starts_with("lk_"));
}

#[tokio::test]
async fn other_admin_endpoints_are_404() {
    let (_dir, admin) = build_admin().await;
    let state = BootstrapState {
        admin: Arc::new(admin),
    };
    let app = build_router(state);
    let server = TestServer::new(app);

    // The bootstrap-only listener exposes nothing but register. Probe
    // every M2 admin route shape and verify 404.
    for path in [
        "/admin/agent/status",
        "/admin/agent/rotate",
        "/admin/agent/deregister",
        "/admin/operator/agents",
        "/admin/operator/audit",
    ] {
        let resp = server.get(path).await;
        resp.assert_status(axum::http::StatusCode::NOT_FOUND);
    }
}
