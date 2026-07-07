//! Phase J / M2 (WEM-448, LOG-3) — operational-log query route.
//!
//! `GET /admin/operator/logs` reads the `operational_logs` table (distinct
//! from `/audit`). Covers:
//!   - a query returns emitted rows under the `logs` envelope;
//!   - filtering by level + component;
//!   - an invalid `level` or `component` → 400 (mirrors `/audit`'s
//!     invalid_event_class / invalid_decision handling).

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::auth_v2::{BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::{
    AgentRepository, BootstrapTokenRepository, LogComponent, LogLevel, OperationalLogStore,
};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use std::sync::Arc;
use tempfile::TempDir;

struct Harness {
    server: TestServer,
    op_token: String,
    _dir: TempDir,
}

async fn setup() -> (Harness, OperationalLogStore) {
    let dir = TempDir::new().unwrap();

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
    let store = OperationalLogStore::new(pool.clone());

    let cfg =
        parse_config_str("listen:\n  host: \"127.0.0.1\"\n  port: 9200\ntools: []\n").unwrap();
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
        agent_creds: None,
        credential_sealing_key: None,
        credential_secrets: None,
        operational_log: None,
        operational_log_store: Some(store.clone()),
    };
    let server = TestServer::new(build_router(state));

    (
        Harness {
            server,
            op_token: op_token_wire,
            _dir: dir,
        },
        store,
    )
}

fn auth(h: &Harness) -> String {
    format!("Bearer {}", h.op_token)
}

#[tokio::test]
async fn logs_query_returns_emitted_rows() {
    let (h, store) = setup().await;
    store
        .insert(
            LogLevel::Info,
            LogComponent::Config,
            "config_loaded",
            "daemon configuration loaded",
            None,
        )
        .await
        .unwrap();
    store
        .insert(
            LogLevel::Warn,
            LogComponent::Oauth,
            "oauth_refresh_degraded",
            "refresh failed",
            None,
        )
        .await
        .unwrap();

    let resp = h
        .server
        .get("/admin/operator/logs")
        .add_header("authorization", auth(&h))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let logs = body["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 2);
    // Newest first.
    assert_eq!(logs[0]["event"], "oauth_refresh_degraded");
    assert_eq!(logs[0]["component"], "oauth");
    assert_eq!(logs[0]["level"], "warn");
}

#[tokio::test]
async fn logs_query_filters_by_level_and_component() {
    let (h, store) = setup().await;
    store
        .insert(LogLevel::Info, LogComponent::Config, "a", "m", None)
        .await
        .unwrap();
    store
        .insert(LogLevel::Warn, LogComponent::Oauth, "b", "m", None)
        .await
        .unwrap();

    let resp = h
        .server
        .get("/admin/operator/logs?level=warn&component=oauth")
        .add_header("authorization", auth(&h))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let logs = body["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0]["event"], "b");
}

#[tokio::test]
async fn logs_query_rejects_bad_level() {
    let (h, _store) = setup().await;
    let resp = h
        .server
        .get("/admin/operator/logs?level=critical")
        .add_header("authorization", auth(&h))
        .await;
    assert_eq!(resp.status_code(), 400);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "invalid_level");
}

#[tokio::test]
async fn logs_query_rejects_bad_component() {
    let (h, _store) = setup().await;
    let resp = h
        .server
        .get("/admin/operator/logs?component=database")
        .add_header("authorization", auth(&h))
        .await;
    assert_eq!(resp.status_code(), 400);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "invalid_component");
}
