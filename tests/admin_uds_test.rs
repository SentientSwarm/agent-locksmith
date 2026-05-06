//! Admin UDS end-to-end integration tests.
//!
//! Covers T2.12 (AdminService), T2.13 (UDS), T2.14 (middleware),
//! T2.15 (agent self-service handlers), and T2.16 (operator handlers).
//! Demonstrates UC-1 (operator-driven register), UC-3 (agent status),
//! UC-4 (operator-initiated revoke), UC-5 (bootstrap-token register).

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::auth_v2::{BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::{AgentRepository, BootstrapTokenRepository};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;

struct Harness {
    server: TestServer,
    op_token_wire: String,
    _dir: TempDir,
}

async fn setup() -> Harness {
    let dir = TempDir::new().unwrap();

    // Operator credentials file with one operator.
    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_token_wire = op_token.wire_format();
    let token_hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_token.secret.expose().to_string(),
    ))
    .unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_token.public_id.as_str(),
            token_hash
        ),
    )
    .unwrap();

    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool.clone());

    // Minimal config with no tools (we only exercise admin endpoints).
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

    let admin = Arc::new(AdminService::new(agents.clone(), bootstrap, config));
    let agent_auth = Arc::new(BearerAuthenticator::new(agents).unwrap());
    let operator_auth = Arc::new(OperatorAuthenticator::load(&ops_path).unwrap());

    let state = UdsState {
        admin,
        agent_auth,
        operator_auth,
        operator_mtls: None,
        registrations: None,
        catalog: None,
        resolved_creds: None,
        oauth: None,
    };
    let router = build_router(state);
    let server = TestServer::new(router);

    Harness {
        server,
        op_token_wire,
        _dir: dir,
    }
}

#[tokio::test]
async fn uc1_operator_creates_agent_directly() {
    let h = setup().await;
    let resp = h
        .server
        .post("/admin/operator/agents")
        .add_header("authorization", format!("Bearer {}", h.op_token_wire))
        .json(&json!({ "name": "agent-7", "description": "test" }))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert!(
        body["public_id"].as_str().unwrap().starts_with("ag_") || body["public_id"].is_string()
    );
    assert!(body["token"].as_str().unwrap().starts_with("lk_"));
}

#[tokio::test]
async fn uc5_bootstrap_mint_then_register_then_status() {
    let h = setup().await;

    // Step 1: operator mints a bootstrap token.
    let mint_resp = h
        .server
        .post("/admin/operator/bootstrap_tokens")
        .add_header("authorization", format!("Bearer {}", h.op_token_wire))
        .json(&json!({ "single_use": true, "tool_allowlist": ["github"] }))
        .await;
    mint_resp.assert_status_ok();
    let mint_body: serde_json::Value = mint_resp.json();
    let bootstrap_token = mint_body["token"].as_str().unwrap().to_string();
    assert!(bootstrap_token.starts_with("lkbt_"));

    // Step 2: agent presents bootstrap token at /admin/agent/register.
    let reg_resp = h
        .server
        .post("/admin/agent/register")
        .json(&json!({
            "bootstrap_token": bootstrap_token,
            "name": "agent-bootstrap"
        }))
        .await;
    reg_resp.assert_status_ok();
    let reg_body: serde_json::Value = reg_resp.json();
    let agent_token = reg_body["token"].as_str().unwrap().to_string();
    assert!(agent_token.starts_with("lk_"));

    // Step 3: agent calls /admin/agent/status with its token (UC-3).
    let status_resp = h
        .server
        .get("/admin/agent/status")
        .add_header("authorization", format!("Bearer {agent_token}"))
        .await;
    status_resp.assert_status_ok();
    let status_body: serde_json::Value = status_resp.json();
    assert_eq!(status_body["name"], "agent-bootstrap");
}

#[tokio::test]
async fn uc4_operator_revokes_agent_and_subsequent_auth_fails() {
    let h = setup().await;

    // Create an agent via operator path.
    let create_resp = h
        .server
        .post("/admin/operator/agents")
        .add_header("authorization", format!("Bearer {}", h.op_token_wire))
        .json(&json!({ "name": "compromised" }))
        .await;
    create_resp.assert_status_ok();
    let create_body: serde_json::Value = create_resp.json();
    let agent_token = create_body["token"].as_str().unwrap().to_string();
    let public_id = create_body["public_id"].as_str().unwrap().to_string();

    // Verify status works pre-revoke.
    let pre = h
        .server
        .get("/admin/agent/status")
        .add_header("authorization", format!("Bearer {agent_token}"))
        .await;
    pre.assert_status_ok();

    // Operator revokes.
    let rev = h
        .server
        .post(&format!("/admin/operator/agents/{public_id}/revoke"))
        .add_header("authorization", format!("Bearer {}", h.op_token_wire))
        .await;
    rev.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Subsequent auth fails with 401.
    let post = h
        .server
        .get("/admin/agent/status")
        .add_header("authorization", format!("Bearer {agent_token}"))
        .await;
    post.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn operator_endpoint_rejects_agent_token() {
    let h = setup().await;
    // Create an agent for a real agent token.
    let create_resp = h
        .server
        .post("/admin/operator/agents")
        .add_header("authorization", format!("Bearer {}", h.op_token_wire))
        .json(&json!({ "name": "regular" }))
        .await;
    create_resp.assert_status_ok();
    let agent_token = create_resp.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // Agent token at operator endpoint → 401 (namespace mismatch).
    let resp = h
        .server
        .get("/admin/operator/agents")
        .add_header("authorization", format!("Bearer {agent_token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_endpoint_rejects_operator_token() {
    let h = setup().await;
    // Operator token at agent endpoint → 401.
    let resp = h
        .server
        .get("/admin/agent/status")
        .add_header("authorization", format!("Bearer {}", h.op_token_wire))
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_self_rotate_invalidates_old_token() {
    let h = setup().await;
    let create_resp = h
        .server
        .post("/admin/operator/agents")
        .add_header("authorization", format!("Bearer {}", h.op_token_wire))
        .json(&json!({ "name": "rotater" }))
        .await;
    create_resp.assert_status_ok();
    let body: serde_json::Value = create_resp.json();
    let token_v1 = body["token"].as_str().unwrap().to_string();
    // The current_secret is the part after the `.` in the token.
    let secret_v1 = token_v1.split_once('.').unwrap().1.to_string();

    let rot = h
        .server
        .post("/admin/agent/rotate")
        .add_header("authorization", format!("Bearer {token_v1}"))
        .json(&json!({ "current_secret": secret_v1 }))
        .await;
    rot.assert_status_ok();
    let token_v2 = rot.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(token_v1, token_v2);

    // Old token now fails (D-13).
    let old = h
        .server
        .get("/admin/agent/status")
        .add_header("authorization", format!("Bearer {token_v1}"))
        .await;
    old.assert_status(axum::http::StatusCode::UNAUTHORIZED);

    // New token works.
    let new = h
        .server
        .get("/admin/agent/status")
        .add_header("authorization", format!("Bearer {token_v2}"))
        .await;
    new.assert_status_ok();
}
