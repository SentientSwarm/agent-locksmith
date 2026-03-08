use axum_test::{TestResponse, TestServer};
use agent_locksmith::app::build_app;
use agent_locksmith::config::AppConfig;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_full_proxy_flow() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("x-api-key", "real-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"results": [{"title": "test"}]})),
        )
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "agent-token"
tools:
  - name: "tavily"
    description: "Tavily search"
    upstream: "{}"
    auth:
      header: "x-api-key"
      value: "real-key"
    timeout_seconds: 15
"#,
        mock.uri()
    );

    let config: AppConfig = serde_yaml::from_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app);

    // 1. Health works without auth
    let resp: TestResponse = server.get("/health").await;
    resp.assert_status_ok();
    let health: serde_json::Value = resp.json();
    assert_eq!(health["tools"][0], "tavily");

    // 2. Discovery requires auth
    let resp: TestResponse = server.get("/tools").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);

    // 3. Discovery works with correct auth
    let resp: TestResponse = server
        .get("/tools")
        .add_header(
            "Authorization",
            "Bearer agent-token",
        )
        .await;
    resp.assert_status_ok();

    // 4. Proxy injects credentials
    let resp: TestResponse = server
        .post("/api/tavily/v1/search")
        .add_header(
            "Authorization",
            "Bearer agent-token",
        )
        .json(&serde_json::json!({"query": "rust proxy"}))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["results"][0]["title"], "test");

    // 5. Unknown tool returns 404
    let resp: TestResponse = server
        .get("/api/unknown/test")
        .add_header(
            "Authorization",
            "Bearer agent-token",
        )
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}
