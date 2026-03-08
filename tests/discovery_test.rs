use agent_locksmith::app::build_app;
use agent_locksmith::config::AppConfig;
use axum_test::{TestResponse, TestServer};

#[tokio::test]
async fn test_tools_returns_active_tools() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub REST API"
    upstream: "https://api.github.com"
    cloud: true
    auth:
      header: "Authorization"
      value: "Bearer test-token"
    timeout_seconds: 30
  - name: "tavily"
    description: "Tavily search"
    upstream: "https://api.tavily.com"
    auth:
      header: "x-api-key"
      value: ""
    timeout_seconds: 15
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/tools").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let tools = body["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "github");
    assert_eq!(tools[0]["type"], "api");
    assert_eq!(tools[0]["path"], "/api/github");
    assert_eq!(tools[0]["description"], "GitHub REST API");
}

#[tokio::test]
async fn test_tools_no_credentials_in_response() {
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
      value: "Bearer super-secret-token"
    timeout_seconds: 30
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/tools").await;
    let body_str = resp.text();
    assert!(!body_str.contains("super-secret-token"));
}
