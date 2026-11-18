//! Agent-listener authentication. Legacy shared-bearer mode was removed
//! in 3.0.0 (AGENT-297, AGENT-318): every request but the probes needs
//! an enrolled agent's credential, and `inbound_auth` grants nothing.

#[path = "support/registered_legacy.rs"]
mod registered_legacy;

use agent_locksmith::app::build_app;
use agent_locksmith::config::parse_config_str;
use axum::http::StatusCode;
use axum_test::TestServer;

const SHARED: &str = r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "my-secret-token"
tools: []
"#;

#[tokio::test]
async fn probes_need_no_credential() {
    let f = registered_legacy::setup(parse_config_str(SHARED).unwrap()).await;
    for probe in ["/health", "/livez", "/readyz", "/version"] {
        f.server.get(probe).await.assert_status_ok();
    }
}

#[tokio::test]
async fn a_missing_credential_is_refused() {
    let f = registered_legacy::setup(parse_config_str(SHARED).unwrap()).await;
    f.server
        .get("/tools")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_shared_inbound_auth_token_is_not_a_credential() {
    let f = registered_legacy::setup(parse_config_str(SHARED).unwrap()).await;
    f.server
        .get("/tools")
        .add_header("Authorization", "Bearer my-secret-token")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_enrolled_agent_is_admitted() {
    let f = registered_legacy::authed(parse_config_str(SHARED).unwrap()).await;
    f.server.get("/tools").await.assert_status_ok();
}

/// A router built without an agent authenticator is miswired: it fails
/// closed instead of serving identityless requests.
#[tokio::test]
async fn an_app_without_an_agent_authenticator_fails_closed() {
    let server = TestServer::new(build_app(parse_config_str(SHARED).unwrap()));
    for path in ["/tools", "/models", "/api/any/thing"] {
        let resp = server
            .get(path)
            .add_header("Authorization", "Bearer my-secret-token")
            .await;
        resp.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            resp.json::<serde_json::Value>()["error"]["code"],
            "internal_error"
        );
    }
    server.get("/livez").await.assert_status_ok();
}
