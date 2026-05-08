//! T7.3 — size cap end-to-end (streaming + non-streaming).

use agent_locksmith::app::build_app;
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository};
use axum_test::TestServer;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config_yaml(upstream: &str, cap: u64, with_redaction: bool) -> String {
    let redaction_block = if with_redaction {
        r#"
      redaction_patterns:
        - id: nope
          regex: "wont-match-anything"
"#
    } else {
        ""
    };
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: t
    description: t
    upstream: "{upstream}"
    response:
      max_size_bytes: {cap}{redaction_block}
"#
    )
}

#[tokio::test]
async fn streaming_under_cap_passes_unchanged() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/small"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
        .mount(&mock)
        .await;
    let cfg = parse_config_str(&config_yaml(&mock.uri(), 1024, false)).unwrap();
    let server = TestServer::new(build_app(cfg));
    let resp = server.get("/api/t/small").await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "hello");
}

#[tokio::test]
async fn streaming_over_cap_emits_truncation_marker() {
    let mock = MockServer::start().await;
    let big = "X".repeat(500);
    Mock::given(method("GET"))
        .and(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_string(big))
        .mount(&mock)
        .await;
    let cfg = parse_config_str(&config_yaml(&mock.uri(), 50, false)).unwrap();
    let server = TestServer::new(build_app(cfg));
    let resp = server.get("/api/t/big").await;
    // Status comes from upstream (200) — truncation is body-level.
    resp.assert_status_ok();
    let body = resp.text();
    // Prefix that fits in the cap is 50 X's.
    assert!(body.starts_with(&"X".repeat(50)), "prefix: {body}");
    assert!(body.contains("response_size_exceeded"), "marker: {body}");
}

#[tokio::test]
async fn nonstreaming_over_cap_returns_502() {
    // Adding a redaction pattern triggers the buffered (non-streaming)
    // code path even though our pattern won't match anything.
    let mock = MockServer::start().await;
    let big = "Y".repeat(500);
    Mock::given(method("GET"))
        .and(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_string(big))
        .mount(&mock)
        .await;
    let cfg = parse_config_str(&config_yaml(&mock.uri(), 50, true)).unwrap();
    let server = TestServer::new(build_app(cfg));
    let resp = server.get("/api/t/big").await;
    resp.assert_status(axum::http::StatusCode::BAD_GATEWAY);
    let body: serde_json::Value = resp.json();
    assert_eq!(
        body["error"]["type"].as_str(),
        Some("response_size_exceeded")
    );
}

#[tokio::test]
async fn streaming_truncation_emits_audit_row() {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let audit = AuditRepository::new(pool);

    let mock = MockServer::start().await;
    let big = "Z".repeat(500);
    Mock::given(method("GET"))
        .and(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_string(big))
        .mount(&mock)
        .await;
    let cfg = parse_config_str(&config_yaml(&mock.uri(), 50, false)).unwrap();
    let shared = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(cfg));
    let app = agent_locksmith::app::build_app_with_audit(shared, Some(audit.clone()));
    let server = TestServer::new(app);
    let _ = server.get("/api/t/big").await;

    // Give the truncation-spawned audit task a moment to land.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r.event == "response_size_exceeded")
        .expect("response_size_exceeded audit row exists");
    let details = row.details.as_ref().unwrap();
    assert_eq!(details["cap_bytes"].as_u64(), Some(50));
    assert_eq!(details["flow"].as_str(), Some("streaming"));
}
