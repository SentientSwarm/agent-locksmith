use agent_locksmith::app::build_app;
use agent_locksmith::config::AppConfig;
use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

async fn mount_mcp_handshake(mock: &MockServer, mcp_path: &str, tool_description: &str) {
    let tool_description = tool_description.to_string();
    Mock::given(method("POST"))
        .and(path(mcp_path))
        .and(header("authorization", "Bearer kamiwaza-token"))
        .respond_with(move |request: &Request| {
            let payload: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or_else(|_| serde_json::json!({}));
            match payload.get("method").and_then(|value| value.as_str()) {
                Some("initialize") => ResponseTemplate::new(200)
                    .insert_header("mcp-session-id", "test-session")
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {"tools": {"listChanged": false}},
                            "serverInfo": {"name": "tool-z", "version": "1.0.0"}
                        }
                    })),
                Some("notifications/initialized") => {
                    ResponseTemplate::new(202).set_body_json(serde_json::json!({}))
                }
                Some("tools/list") => ResponseTemplate::new(200)
                    .insert_header("mcp-session-id", "test-session")
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 2,
                        "result": {
                            "tools": [{
                                "name": "search",
                                "description": tool_description,
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "query": {"type": "string"},
                                        "gl": {"type": "string"}
                                    },
                                    "required": ["query"]
                                }
                            }]
                        }
                    })),
                Some("tools/call") => {
                    let query = payload
                        .pointer("/params/arguments/query")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default();
                    if query != "latest openclaw news" {
                        return ResponseTemplate::new(400)
                            .set_body_json(serde_json::json!({"error": "unexpected query"}));
                    }
                    ResponseTemplate::new(200)
                        .insert_header("mcp-session-id", "test-session")
                        .set_body_json(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": 3,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": "{\"organic\":[{\"title\":\"OpenClaw news\"}]}"
                                }]
                            }
                        }))
                }
                _ => ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "unexpected MCP method"})),
            }
        })
        .mount(mock)
        .await;
}

fn build_config(mock: &MockServer) -> AppConfig {
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
kamiwaza:
  enabled: true
  api_url: "{api_url}"
  api_token: "kamiwaza-token"
  verify_tls: true
  timeout_seconds: 5
tools: []
"#,
        api_url = mock.uri()
    );
    serde_yaml::from_str(&yaml).unwrap()
}

async fn mount_extensions(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/extensions"))
        .and(header("authorization", "Bearer kamiwaza-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "name": "tool-z-19607be6",
                "type": "tool",
                "version": "1.0.0",
                "phase": "Running",
                "services": [{"name": "primary", "ready": true, "available_replicas": 1}],
                "endpoints": {"external": format!("{}/runtime/tools/tool-z-19607be6", mock.uri())}
            },
            {
                "name": "stopped-tool",
                "type": "tool",
                "version": "1.0.0",
                "phase": "Failed",
                "services": [{"name": "primary", "ready": true, "available_replicas": 1}],
                "endpoints": {"external": format!("{}/runtime/tools/stopped-tool", mock.uri())}
            }
        ])))
        .mount(mock)
        .await;
}

#[tokio::test]
async fn test_kamiwaza_tools_are_discovered_without_exposing_token() {
    let mock = MockServer::start().await;
    mount_extensions(&mock).await;
    mount_mcp_handshake(
        &mock,
        "/runtime/tools/tool-z-19607be6/mcp",
        "Search Google using Serper API.",
    )
    .await;

    let app = build_app(build_config(&mock));
    let server = TestServer::new(app);

    let resp: TestResponse = server.get("/tools").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let tools = body["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "kamiwaza_tool_z_19607be6_search");
    assert_eq!(tools[0]["type"], "mcp");
    assert_eq!(tools[0]["path"], "/api/kamiwaza_tool_z_19607be6_search");
    assert_eq!(tools[0]["mcpTool"], "search");
    assert_eq!(tools[0]["inputSchema"]["required"][0], "query");

    let rendered = body.to_string();
    assert!(!rendered.contains("kamiwaza-token"));
}

#[tokio::test]
async fn test_kamiwaza_tool_invocation_calls_mcp_with_injected_bearer() {
    let mock = MockServer::start().await;
    mount_extensions(&mock).await;
    mount_mcp_handshake(
        &mock,
        "/runtime/tools/tool-z-19607be6/mcp",
        "Search Google using Serper API.",
    )
    .await;

    Mock::given(method("DELETE"))
        .and(path("/runtime/tools/tool-z-19607be6/mcp"))
        .and(header("authorization", "Bearer kamiwaza-token"))
        .and(header("mcp-session-id", "test-session"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;

    let app = build_app(build_config(&mock));
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .post("/api/kamiwaza_tool_z_19607be6_search")
        .json(&serde_json::json!({
            "query": "latest openclaw news",
            "category": "search",
            "gl": "us"
        }))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["content"][0]["type"], "text");
    assert!(
        body["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("OpenClaw news")
    );
}

#[tokio::test]
async fn test_kamiwaza_missing_token_fails_closed_for_proxy_calls() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
kamiwaza:
  enabled: true
  api_url: "http://127.0.0.1:1"
tools: []
"#;
    let app = build_app(serde_yaml::from_str(yaml).unwrap());
    let server = TestServer::new(app);

    let resp: TestResponse = server
        .post("/api/kamiwaza_tool_z_19607be6_search")
        .json(&serde_json::json!({"query": "latest openclaw news"}))
        .await;
    resp.assert_status(StatusCode::BAD_GATEWAY);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["type"], "upstream_error");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no API token")
    );
}
