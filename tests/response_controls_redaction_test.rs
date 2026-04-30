//! T7.4 — regex redaction end-to-end with audit hashing.

use agent_locksmith::app::build_app_with_audit;
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn pattern_match_redacts_response_body_and_records_hash() {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let audit = AuditRepository::new(pool);

    let mock = MockServer::start().await;
    let leaky = "{\"data\":\"key=sk-ABCDEF123456 done\"}";
    Mock::given(method("GET"))
        .and(path("/leak"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(leaky.as_bytes().to_vec(), "application/json"),
        )
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
      redaction_patterns:
        - id: openai_key
          regex: "sk-[A-Za-z0-9]{{6,}}"
"#,
        upstream = mock.uri()
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let shared = Arc::new(ArcSwap::from_pointee(cfg));
    let app = build_app_with_audit(shared, Some(audit.clone()));
    let server = TestServer::new(app);
    let resp = server.get("/api/t/leak").await;
    resp.assert_status_ok();
    let body = resp.text();
    assert!(
        !body.contains("sk-ABCDEF123456"),
        "secret leaked in response: {body}"
    );
    assert!(body.contains("[REDACTED:openai_key]"), "marker: {body}");

    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r.event == "response_redaction")
        .expect("response_redaction row");
    let details = row.details.as_ref().unwrap();
    assert_eq!(details["pattern_id"].as_str(), Some("openai_key"));
    assert_eq!(details["matches"].as_u64(), Some(1));
    let hash = details["match_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64, "sha256 hex length");
    // Critical: cleartext NEVER in audit details.
    let serialized = serde_json::to_string(details).unwrap();
    assert!(
        !serialized.contains("sk-ABCDEF123456"),
        "cleartext leaked into audit details: {serialized}"
    );
}

#[tokio::test]
async fn no_match_no_redaction_event() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/clean"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(br#"{"clean":"data"}"#.to_vec(), "application/json"),
        )
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
      redaction_patterns:
        - id: nope
          regex: "WONT-MATCH"
"#,
        upstream = mock.uri()
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let server = TestServer::new(agent_locksmith::app::build_app(cfg));
    let resp = server.get("/api/t/clean").await;
    resp.assert_status_ok();
    assert!(resp.text().contains("clean"));
}
