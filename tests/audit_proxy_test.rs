//! T3.1 — proxy hot path emits one audit row per request.
//!
//! Covers R-F7 + INF-19. The proxy_handler must record an AuditEvent
//! into the AuditRepository for every request it dispatches. This file
//! exercises the M0/M1 shared-bearer code path explicitly (built via
//! `build_app_with_audit`, which passes `bearer_authenticator: None`
//! to `build_app_full`) so `agent_public_id` is None on these rows by
//! design. Per-agent identity on the proxy is wired by M9 / B1 — see
//! `tests/proxy_acl_test.rs` for the populated-`agent_public_id` flow.

use agent_locksmith::app::build_app_with_audit;
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository, Decision, EventClass};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn fixture() -> (TempDir, AuditRepository) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    (dir, AuditRepository::new(pool))
}

#[tokio::test]
async fn proxy_records_audit_row_on_success() {
    let (_dir, audit) = fixture().await;
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/things/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "things"
    description: "Things service"
    upstream: "{}"
    timeouts:
      request_seconds: 5
      idle_seconds: 5
"#,
        mock.uri()
    );
    let config = parse_config_str(&yaml).unwrap();
    let shared = Arc::new(ArcSwap::from_pointee(config));
    let app = build_app_with_audit(shared, Some(audit.clone()));
    let server = TestServer::new(app);

    let resp = server.get("/api/things/v1/things/42").await;
    resp.assert_status_ok();

    // Audit record visible after the request returns.
    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .expect("query ok");
    assert_eq!(rows.len(), 1, "one audit row per proxied request");
    let row = &rows[0];
    assert_eq!(row.event_class, EventClass::Proxy);
    assert_eq!(row.event, "proxy_request");
    assert_eq!(row.tool.as_deref(), Some("things"));
    assert_eq!(row.method.as_deref(), Some("GET"));
    assert!(
        row.path.as_deref().unwrap().contains("v1/things/42"),
        "path captured; got: {:?}",
        row.path
    );
    assert_eq!(row.status, Some(200));
    assert_eq!(row.decision, Decision::Allowed);
    assert!(
        row.latency_ms.is_some_and(|l| l < 5_000),
        "latency populated and reasonable"
    );
    assert!(
        row.agent_public_id.is_none(),
        "M0/M1 shared-bearer path: agent_public_id is None by construction. \
         The per-agent populated case is covered by tests/proxy_acl_test.rs (M9)."
    );
}

#[tokio::test]
async fn proxy_records_decision_error_on_upstream_5xx() {
    let (_dir, audit) = fixture().await;
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/explode"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock)
        .await;
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "svc"
    description: "x"
    upstream: "{}"
"#,
        mock.uri()
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let shared = Arc::new(ArcSwap::from_pointee(cfg));
    let app = build_app_with_audit(shared, Some(audit.clone()));
    let server = TestServer::new(app);

    let resp = server.get("/api/svc/explode").await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);

    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, Some(503));
    assert_eq!(rows[0].decision, Decision::Error);
}

#[tokio::test]
async fn proxy_records_unknown_tool_as_denied() {
    let (_dir, audit) = fixture().await;
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let cfg = parse_config_str(yaml).unwrap();
    let shared = Arc::new(ArcSwap::from_pointee(cfg));
    let app = build_app_with_audit(shared, Some(audit.clone()));
    let server = TestServer::new(app);

    let resp = server.get("/api/no-such-tool/anything").await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);

    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.decision, Decision::Denied);
    assert_eq!(row.event, "tool_not_found");
    assert_eq!(row.tool.as_deref(), Some("no-such-tool"));
}

#[tokio::test]
async fn proxy_without_audit_repo_still_works() {
    // Backward compat: the M0/M1 path doesn't have an audit repo. The
    // proxy must keep working without it.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "svc"
    description: "x"
    upstream: "{}"
"#,
        mock.uri()
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let shared = Arc::new(ArcSwap::from_pointee(cfg));
    let app = build_app_with_audit(shared, None);
    let server = TestServer::new(app);
    let resp = server.get("/api/svc/ok").await;
    resp.assert_status_ok();
}
