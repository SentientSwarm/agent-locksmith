//! T3.1 — proxy hot path emits one audit row per request.
//!
//! Covers R-F7 + INF-19. The proxy_handler must record an AuditEvent
//! into the AuditRepository for every request it dispatches. Requests
//! come from an enrolled agent (legacy identityless mode was removed in
//! 3.0.0, AGENT-318), so rows carry its `agent_public_id`.

#[path = "support/registered_legacy.rs"]
mod registered_legacy;

use agent_locksmith::config::parse_config_str;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, Decision, EventClass};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn proxy_records_audit_row_on_success() {
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
    let f = registered_legacy::authed(parse_config_str(&yaml).unwrap()).await;
    let (server, audit) = (&f.server, &f.audit);

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
        row.agent_public_id.is_some(),
        "every proxied request comes from an enrolled agent"
    );
}

#[tokio::test]
async fn proxy_records_decision_error_on_upstream_5xx() {
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
    let f = registered_legacy::authed(parse_config_str(&yaml).unwrap()).await;
    let (server, audit) = (&f.server, &f.audit);

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

/// An agent asking for a tool outside its allowlist is denied before
/// resolution, so an unknown name looks like any refused one (M9).
#[tokio::test]
async fn proxy_records_unknown_tool_as_denied() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let f = registered_legacy::authed(parse_config_str(yaml).unwrap()).await;
    let (server, audit) = (&f.server, &f.audit);

    let resp = server.get("/api/no-such-tool/anything").await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.decision, Decision::Denied);
    assert_eq!(row.event, "authz_denied");
    assert_eq!(row.tool.as_deref(), Some("no-such-tool"));
}

#[tokio::test]
async fn proxy_without_audit_repo_still_works() {
    // The proxy must keep working when no audit repository is wired.
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
    let f = registered_legacy::authed_without_audit(parse_config_str(&yaml).unwrap()).await;
    let resp = f.server.get("/api/svc/ok").await;
    resp.assert_status_ok();
}
