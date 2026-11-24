//! T1.11 — /livez, /readyz, /version (split from M0 /health). INF-3 / Q-18.

#[path = "support/registered_legacy.rs"]
mod registered;

use agent_locksmith::app::build_app;
use agent_locksmith::config::parse_config_str;
use axum_test::{TestResponse, TestServer};

fn server_with_yaml(yaml: &str) -> TestServer {
    let config = parse_config_str(yaml).unwrap();
    TestServer::new(build_app(config))
}

#[tokio::test]
async fn test_livez_returns_ok() {
    let server = server_with_yaml(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#,
    );
    let resp: TestResponse = server.get("/livez").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["status"], "live");
    assert!(body["uptime_seconds"].is_number());
}

#[tokio::test]
async fn test_health_alias_to_livez_for_backward_compat() {
    // M0 deployments probe /health; v2 keeps it as an alias to /livez.
    let server = server_with_yaml(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#,
    );
    let resp: TestResponse = server.get("/health").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["status"], "live");
}

#[tokio::test]
async fn test_readyz_ok_when_no_tools() {
    let server = server_with_yaml(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#,
    );
    let resp: TestResponse = server.get("/readyz").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["status"], "ready");
}

#[tokio::test]
async fn test_readyz_ok_when_tool_credential_present() {
    let h = registered::setup(
        parse_config_str(
            r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub"
    upstream: "https://api.github.com"
    egress: "proxied"
    auth:
      header: "Authorization"
      value: "Bearer real-token"
"#,
        )
        .unwrap(),
    )
    .await;
    let server = &h.server;
    let resp: TestResponse = server.get("/readyz").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["status"], "ready");
}

#[tokio::test]
async fn test_readyz_503_when_tool_credential_missing() {
    // Tool declares an auth block but the credential resolves to empty
    // (typical when the operator's env var is unset). M1 treats every
    // tool as required (degraded-mode opt-out is M2 / INF-4).
    let h = registered::setup(
        parse_config_str(
            r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "tavily"
    description: "Tavily"
    upstream: "https://api.tavily.com"
    egress: "proxied"
    auth:
      header: "x-api-key"
      value: ""
"#,
        )
        .unwrap(),
    )
    .await;
    let server = &h.server;
    let resp: TestResponse = server.get("/readyz").await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["reason"], "tool_credentials_unresolved");
    assert_eq!(body["tools"][0], "tavily");
}

#[tokio::test]
async fn test_version_returns_build_metadata() {
    let server = server_with_yaml(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#,
    );
    let resp: TestResponse = server.get("/version").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["name"], env!("CARGO_PKG_NAME"));
    assert_eq!(
        body,
        agent_locksmith::build_info::document(env!("CARGO_PKG_NAME"))
    );
}

#[tokio::test]
async fn test_health_endpoints_bypass_auth() {
    // INF-3: orchestrators should not need credentials to probe.
    let server = server_with_yaml(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "secret-agent-token"
tools: []
"#,
    );
    for path in ["/livez", "/readyz", "/version", "/health"] {
        let resp: TestResponse = server.get(path).await;
        // /readyz returns 503 if no tools configured? No — empty tools
        // list means no required backends, so /readyz is OK.
        let status = resp.status_code();
        assert!(
            status.is_success() || status == axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{path} should respond without auth (status was {status})"
        );
    }
}

// ─── AGENT-251: database write health ─────────────────────────────────

fn open_tool_yaml(upstream: &str) -> String {
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "open"
    description: "authless upstream"
    upstream: "{upstream}"
    egress: "direct"
"#
    )
}

#[tokio::test]
async fn test_readyz_503_while_database_unwritable_then_recovers() {
    let h =
        registered::setup(parse_config_str(&open_tool_yaml("http://127.0.0.1:9")).unwrap()).await;
    h.audit.write_health().failed("test", &"disk I/O error");
    let resp: TestResponse = h.server.get("/readyz").await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["reason"], "database_unwritable");
    h.server.get("/livez").await.assert_status_ok();

    // A successful probe write against the (writable) database clears it.
    agent_locksmith::repo::write_health::probe(&h.audit).await;
    h.server.get("/readyz").await.assert_status_ok();
}

#[tokio::test]
async fn test_proxy_refuses_without_dispatch_while_database_unwritable() {
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};
    let mock = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock)
        .await;
    let h = registered::authed(parse_config_str(&open_tool_yaml(&mock.uri())).unwrap()).await;

    h.audit.write_health().failed("test", &"disk I/O error");
    let resp: TestResponse = h.server.post("/api/open/thing").await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "audit_unavailable");
    assert_eq!(body["error"]["type"], "availability_error");

    // Recovered: the next request is forwarded (the mock's single expected
    // hit) and audited.
    let health = h.audit.write_health();
    health.succeeded(health.begin());
    h.server.get("/api/open/after").await.assert_status_ok();
    mock.verify().await;
}
