#[path = "support/registered_legacy.rs"]
mod registered;
use agent_locksmith::config::parse_config_str;
use axum_test::TestResponse;
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

    let config = parse_config_str(&yaml).unwrap();
    let h = registered::setup(config).await;
    let server = &h.server;

    // 1. Liveness works without auth (health alias preserved for M0)
    let resp: TestResponse = server.get("/livez").await;
    resp.assert_status_ok();
    let live: serde_json::Value = resp.json();
    assert_eq!(live["status"], "live");

    let resp: TestResponse = server.get("/health").await;
    resp.assert_status_ok();

    // 2. Discovery requires auth
    let resp: TestResponse = server.get("/tools").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);

    // 3. Discovery works with correct auth
    let resp: TestResponse = server
        .get("/tools")
        .add_header("Authorization", &h.bearer)
        .await;
    resp.assert_status_ok();

    // 4. Proxy injects credentials
    let resp: TestResponse = server
        .post("/api/tavily/v1/search")
        .add_header("Authorization", &h.bearer)
        .json(&serde_json::json!({"query": "rust proxy"}))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["results"][0]["title"], "test");

    // 5. Unknown tool returns 404
    let resp: TestResponse = server
        .get("/api/unknown/test")
        .add_header("Authorization", &h.bearer)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}
