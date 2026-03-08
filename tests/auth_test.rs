use agent_locksmith::app::build_app;
use agent_locksmith::config::AppConfig;
use axum_test::{TestResponse, TestServer};

#[tokio::test]
async fn test_no_auth_configured_allows_all() {
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
}

#[tokio::test]
async fn test_bearer_auth_rejects_missing_token() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "my-secret-token"
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/tools").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_rejects_wrong_token() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "my-secret-token"
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .get("/tools")
        .add_header("Authorization", "Bearer wrong-token")
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_allows_correct_token() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "my-secret-token"
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .get("/tools")
        .add_header("Authorization", "Bearer my-secret-token")
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn test_health_bypasses_auth() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "my-secret-token"
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/health").await;
    resp.assert_status_ok();
}
