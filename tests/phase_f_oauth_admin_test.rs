//! Phase F.4 — OAuth admin endpoint integration tests.
//!
//! TS-210..TS-214. Covers bootstrap (manual refresh-token path) →
//! status → revoke against a mock OAuth token endpoint.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::auth_v2::{BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::oauth::OauthAdminState;
use agent_locksmith::oauth::refresh::RefreshLockMap;
use agent_locksmith::oauth::sealing::SealingKey;
use agent_locksmith::oauth::session::OauthSessionRepository;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::{AgentRepository, BootstrapTokenRepository};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Harness {
    _dir: TempDir,
    server: TestServer,
    op_token: String,
    mock: MockServer,
}

async fn setup() -> Harness {
    let dir = TempDir::new().unwrap();

    // Mint a real operator credential the same way admin_uds_test does.
    let op = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_token_wire = op.wire_format();
    let token_hash =
        argon2_helper::hash(&secrecy::SecretString::from(op.secret.expose().to_string())).unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op.public_id.as_str(),
            token_hash
        ),
    )
    .unwrap();

    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let sessions = OauthSessionRepository::new(pool.clone());
    let sealing_key = SealingKey::generate().unwrap();

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    // Pre-register an OAuth-shaped registration. Mock token endpoint
    // URL is filled in below.
    let mock = MockServer::start().await;
    let token_url = format!("{}/token", mock.uri());

    let r = Registration::new(
        "codex".to_string(),
        Kind::Model,
        "Test OAuth registration".to_string(),
        "https://api.openai.example.com".to_string(),
        AuthSpec::OauthDeviceCode {
            client_id: "test-client".to_string(),
            scopes: vec!["openai-api".to_string()],
            device_url: format!("{}/device", mock.uri()),
            token_url: token_url.clone(),
            session_label: None,
        },
    );
    registrations.create(&r).await.unwrap();

    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));

    let admin = AdminService::new(agents.clone(), bootstrap, cfg_arc);
    let agent_auth = Arc::new(BearerAuthenticator::new(agents).unwrap());
    let operator_auth = Arc::new(OperatorAuthenticator::load(&ops_path).unwrap());

    let state = UdsState {
        admin: Arc::new(admin),
        agent_auth,
        operator_auth,
        operator_mtls: None,
        registrations: Some(registrations.clone()),
        catalog: Some(catalog_arc.clone()),
        resolved_creds: None,
        oauth: Some(OauthAdminState {
            registrations,
            sessions,
            sealing_key,
            catalog: catalog_arc,
            locks: RefreshLockMap::new(),
        }),
    };
    let router = build_router(state);
    let server = TestServer::new(router);

    Harness {
        _dir: dir,
        server,
        op_token: op_token_wire,
        mock,
    }
}

// ─── TS-210: bootstrap exchanges refresh→access, persists session ──────────
#[tokio::test]
async fn ts210_bootstrap_persists_session_after_first_refresh() {
    let h = setup().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-abc",
            "refresh_token": "refresh-rotated",
            "expires_in": 3600,
            "token_type": "Bearer",
        })))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/admin/operator/oauth/codex/bootstrap")
        .add_header("authorization", format!("Bearer {}", h.op_token))
        .json(&serde_json::json!({"refresh_token": "initial-refresh"}))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["name"], "codex");
    assert_eq!(body["present"], true);
    assert_eq!(body["degraded"], false);
    assert!(body["audit_session_id"].as_str().unwrap().len() == 16);
}

// ─── TS-211: bootstrap on non-OAuth registration → 400 ──────────────────────
#[tokio::test]
async fn ts211_bootstrap_rejects_non_oauth_registration() {
    let h = setup().await;
    let resp = h
        .server
        .post("/admin/operator/oauth/non-existent/bootstrap")
        .add_header("authorization", format!("Bearer {}", h.op_token))
        .json(&serde_json::json!({"refresh_token": "x"}))
        .await;
    resp.assert_status_not_found();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "unknown_name");
}

// ─── TS-212: status returns present:false for un-bootstrapped OAuth tool ───
#[tokio::test]
async fn ts212_status_returns_present_false_when_no_session() {
    let h = setup().await;
    let resp = h
        .server
        .get("/admin/operator/oauth/codex")
        .add_header("authorization", format!("Bearer {}", h.op_token))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["name"], "codex");
    assert_eq!(body["present"], false);
}

// ─── TS-213: revoke is idempotent ──────────────────────────────────────────
#[tokio::test]
async fn ts213_revoke_is_idempotent() {
    let h = setup().await;
    // First revoke: nothing to delete.
    let resp = h
        .server
        .delete("/admin/operator/oauth/codex")
        .add_header("authorization", format!("Bearer {}", h.op_token))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Bootstrap then revoke twice: both 204.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "a",
            "expires_in": 3600,
        })))
        .mount(&h.mock)
        .await;
    h.server
        .post("/admin/operator/oauth/codex/bootstrap")
        .add_header("authorization", format!("Bearer {}", h.op_token))
        .json(&serde_json::json!({"refresh_token": "r"}))
        .await
        .assert_status_ok();
    h.server
        .delete("/admin/operator/oauth/codex")
        .add_header("authorization", format!("Bearer {}", h.op_token))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    // Second revoke after already-deleted.
    h.server
        .delete("/admin/operator/oauth/codex")
        .add_header("authorization", format!("Bearer {}", h.op_token))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
}

// ─── TS-214: bootstrap exchange failure rolls back the half-bootstrapped row ─
#[tokio::test]
async fn ts214_failed_bootstrap_rolls_back() {
    let h = setup().await;
    // Mock returns 401 invalid_grant — refresh token is bogus.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_grant",
        })))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/admin/operator/oauth/codex/bootstrap")
        .add_header("authorization", format!("Bearer {}", h.op_token))
        .json(&serde_json::json!({"refresh_token": "wrong"}))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_GATEWAY);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "oauth_bootstrap_failed");

    // Status afterwards: present:false (rollback worked).
    let status = h
        .server
        .get("/admin/operator/oauth/codex")
        .add_header("authorization", format!("Bearer {}", h.op_token))
        .await;
    status.assert_status_ok();
    let body: serde_json::Value = status.json();
    assert_eq!(body["present"], false);
}
