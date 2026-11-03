use agent_locksmith::config::parse_config_str;
use agent_locksmith::{
    app::build_app_with_audit,
    migrations::open_and_migrate,
    repo::audit::{AuditFilter, AuditPage, AuditRepository, EventClass},
};
use arc_swap::ArcSwap;
use axum::http::StatusCode;
use axum_test::TestServer;
use std::sync::Arc;
use wiremock::MockServer;

#[tokio::test]
async fn isolation_credentialed_legacy_routes_require_real_agent_identity() {
    for inbound in ["", "inbound_auth:\n  mode: bearer\n  token: shared\n"] {
        let mock = MockServer::start().await;
        let yaml = format!(
            "listen:\n  host: 127.0.0.1\n  port: 9200\n{inbound}tools:\n  - name: api\n    description: legacy\n    upstream: {}\n    auth:\n      header: x-api-key\n      value: private-legacy-secret\n",
            mock.uri()
        );
        let (_dir, server, audit) = server(&yaml).await;
        let response = server
            .get("/api/api/check")
            .add_header("authorization", "Bearer shared")
            .await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        assert!(!response.text().contains("private-legacy-secret"));
        assert!(mock.received_requests().await.unwrap().is_empty());
        let rows = audit
            .query(&AuditFilter::default(), AuditPage::default())
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_class, EventClass::Security);
        assert_eq!(rows[0].status, Some(401));
        assert!(!format!("{rows:?}").contains("private-legacy-secret"));
        let ready = server.get("/readyz").await;
        ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            ready.json::<serde_json::Value>()["reason"],
            "agent_identity_required"
        );
        assert!(ready.text().contains("register"));
    }
}

async fn server(yaml: &str) -> (tempfile::TempDir, TestServer, AuditRepository) {
    let dir = tempfile::TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("audit.db"))
        .await
        .unwrap();
    let audit = AuditRepository::new(pool);
    let config = Arc::new(ArcSwap::from_pointee(parse_config_str(yaml).unwrap()));
    let server = TestServer::new(build_app_with_audit(config, Some(audit.clone())));
    (dir, server, audit)
}
