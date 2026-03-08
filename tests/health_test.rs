use agent_locksmith::app::build_app;
use agent_locksmith::config::AppConfig;
use axum_test::{TestResponse, TestServer};

#[tokio::test]
async fn test_health_returns_ok() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub"
    upstream: "https://api.github.com"
    auth:
      header: "Authorization"
      value: "Bearer test-token"
    timeout_seconds: 30
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/health").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert!(body["uptime_seconds"].is_number());
    assert!(body["tools"].is_array());
    assert_eq!(body["tools"][0], "github");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn test_health_empty_tools() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/health").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["tools"].as_array().unwrap().len(), 0);
}
