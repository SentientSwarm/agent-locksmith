//! T7.2 — content-type allowlist end-to-end.

#[path = "support/registered_legacy.rs"]
mod registered_legacy;

use agent_locksmith::config::parse_config_str;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn rejected_content_type_returns_502_with_audit() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/html"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(b"<html/>".to_vec(), "text/html"))
        .mount(&mock)
        .await;
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: t
    description: t
    upstream: "{upstream}"
    response:
      content_type_allowlist: ["application/json"]
"#,
        upstream = mock.uri()
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let f = registered_legacy::authed(cfg).await;
    let (server, audit) = (&f.server, &f.audit);
    let resp = server.get("/api/t/html").await;
    resp.assert_status(axum::http::StatusCode::BAD_GATEWAY);
    let body: serde_json::Value = resp.json();
    assert_eq!(
        body["error"]["type"].as_str(),
        Some("response_content_type_disallowed")
    );

    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r.event == "response_content_type_disallowed")
        .expect("audit row recorded");
    let details = row.details.as_ref().unwrap();
    assert_eq!(details["observed_content_type"].as_str(), Some("text/html"));
}

#[tokio::test]
async fn allowed_content_type_passes_with_charset_suffix() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            br#"{"ok":true}"#.to_vec(),
            "application/json; charset=utf-8",
        ))
        .mount(&mock)
        .await;
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: t
    description: t
    upstream: "{upstream}"
    response:
      content_type_allowlist: ["application/json"]
"#,
        upstream = mock.uri()
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let f = registered_legacy::authed(cfg).await;
    let server = &f.server;
    let resp = server.get("/api/t/json").await;
    resp.assert_status_ok();
}
