#[path = "support/registered_legacy.rs"]
mod registered;
use agent_locksmith::config::parse_config_str;
use axum_test::TestResponse;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_proxy_injects_credentials() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/test"))
        .and(header("Authorization", "Bearer injected-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id": 1, "name": "test-repo"})),
        )
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub"
    upstream: "{}"
    auth:
      header: "Authorization"
      value: "Bearer injected-token"
    timeout_seconds: 30
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let mut h = registered::setup(config).await;
    h.server.add_header("authorization", &h.bearer);
    let server = &h.server;

    let resp: TestResponse = server.get("/api/github/repos/test").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["name"], "test-repo");
}

#[tokio::test]
async fn test_proxy_forwards_query_string() {
    // Regression: axum's `{*path}` capture excludes the query string, so the
    // proxy must re-attach it. Without forwarding, ComfyUI `/view?filename=…`
    // (and any query-driven GET) reaches the upstream stripped and 404s.
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/view"))
        .and(query_param("filename", "img_00001_.png"))
        .and(query_param("type", "output"))
        .respond_with(ResponseTemplate::new(200).set_body_string("PNGBYTES"))
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "comfyui"
    description: "ComfyUI"
    upstream: "{}"
    auth:
      header: "Authorization"
      value: "Bearer x"
    timeout_seconds: 30
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let mut h = registered::setup(config).await;
    h.server.add_header("authorization", &h.bearer);
    let server = &h.server;

    let resp: TestResponse = server
        .get("/api/comfyui/view?filename=img_00001_.png&type=output")
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "PNGBYTES");
}

#[tokio::test]
async fn test_proxy_strips_agent_auth_header() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/test"))
        .and(header("Authorization", "Bearer injected"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "svc"
    description: "Test service"
    upstream: "{}"
    auth:
      header: "Authorization"
      value: "Bearer injected"
    timeout_seconds: 30
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let mut h = registered::setup(config).await;
    h.server.add_header("authorization", &h.bearer);
    let server = &h.server;

    let resp: TestResponse = server
        .get("/api/svc/test")
        .add_header("Authorization", &h.bearer)
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn test_proxy_unknown_tool_denied() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config = parse_config_str(yaml).unwrap();
    let mut h = registered::setup(config).await;
    h.server.add_header("authorization", &h.bearer);
    let server = &h.server;

    let resp: TestResponse = server.get("/api/unknown/test").await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("tool access denied")
    );
}

#[tokio::test]
async fn test_proxy_post_with_body() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("x-api-key", "tavily-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"results": []})))
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "tavily"
    description: "Tavily"
    upstream: "{}"
    auth:
      header: "x-api-key"
      value: "tavily-key"
    timeout_seconds: 15
"#,
        mock.uri()
    );

    let config = parse_config_str(&yaml).unwrap();
    let mut h = registered::setup(config).await;
    h.server.add_header("authorization", &h.bearer);
    let server = &h.server;

    let resp: TestResponse = server
        .post("/api/tavily/v1/search")
        .json(&serde_json::json!({"query": "test"}))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn test_proxy_points_upstream_links_back_at_locksmith() {
    // GitHub-style pagination: absolute `Link` URLs to the upstream must come
    // back as the agent-facing route URL, or the next page bypasses
    // Locksmith. Repeated headers must all survive.
    let mock = MockServer::start().await;
    let next = format!("<{}/orgs/o/repos?page=2>; rel=\"next\"", mock.uri());
    Mock::given(method("GET"))
        .and(path("/orgs/o/repos"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("link", next.as_str())
                .append_header("location", format!("{}/repos/o/r", mock.uri()).as_str())
                .append_header("set-cookie", "a=1")
                .append_header("set-cookie", "b=2")
                .set_body_string("[]"),
        )
        .mount(&mock)
        .await;

    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub"
    upstream: "{}"
    auth:
      header: "Authorization"
      value: "Bearer x"
    timeout_seconds: 30
"#,
        mock.uri()
    );
    let config = parse_config_str(&yaml).unwrap();
    let mut h = registered::setup(config).await;
    h.server.add_header("authorization", &h.bearer);

    let resp: TestResponse = h
        .server
        .get("/api/github/orgs/o/repos")
        .add_header("host", "locksmith.test:9200")
        .await;
    resp.assert_status_ok();
    assert_eq!(
        resp.headers()["link"],
        "<http://locksmith.test:9200/api/github/orgs/o/repos?page=2>; rel=\"next\""
    );
    assert_eq!(
        resp.headers()["location"],
        "http://locksmith.test:9200/api/github/repos/o/r"
    );
    let cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().collect();
    assert_eq!(cookies.len(), 2, "every repeated header reaches the agent");
}
