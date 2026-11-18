//! A credentialed route never serves an identityless caller (AGENT-297,
//! AGENT-318): a miswired router without an agent authenticator fails
//! closed, and the shared `inbound_auth` token authenticates nobody.
//! Neither reaches the upstream or exposes the route's credential.

#[path = "support/registered_legacy.rs"]
mod registered_legacy;

use agent_locksmith::config::parse_config_str;
use agent_locksmith::{
    app::build_app_with_audit,
    migrations::open_and_migrate,
    repo::audit::{AuditFilter, AuditPage, AuditRepository},
};
use arc_swap::ArcSwap;
use axum::http::StatusCode;
use axum_test::TestServer;
use std::sync::Arc;
use wiremock::MockServer;

const SECRET: &str = "private-legacy-secret";

fn yaml(upstream: &str) -> String {
    format!(
        "listen:\n  host: 127.0.0.1\n  port: 9200\ninbound_auth:\n  mode: bearer\n  token: shared\ntools:\n  - name: api\n    description: legacy\n    upstream: {upstream}\n    auth:\n      header: x-api-key\n      value: {SECRET}\n"
    )
}

#[tokio::test]
async fn a_router_without_an_agent_authenticator_serves_no_one() {
    let mock = MockServer::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("audit.db"))
        .await
        .unwrap();
    let audit = AuditRepository::new(pool);
    let config = Arc::new(ArcSwap::from_pointee(
        parse_config_str(&yaml(&mock.uri())).unwrap(),
    ));
    let server = TestServer::new(build_app_with_audit(config, Some(audit.clone())));
    for bearer in [None, Some("Bearer shared")] {
        let mut request = server.get("/api/api/check");
        if let Some(b) = bearer {
            request = request.add_header("authorization", b);
        }
        let response = request.await;
        response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.text().contains(SECRET));
    }
    assert!(mock.received_requests().await.unwrap().is_empty());
    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert!(!format!("{rows:?}").contains(SECRET));
}

#[tokio::test]
async fn the_shared_token_does_not_reach_a_credentialed_route() {
    let mock = MockServer::start().await;
    let f = registered_legacy::setup(parse_config_str(&yaml(&mock.uri())).unwrap()).await;
    let response = f
        .server
        .get("/api/api/check")
        .add_header("authorization", "Bearer shared")
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
    assert!(!response.text().contains(SECRET));
    assert!(mock.received_requests().await.unwrap().is_empty());
}
