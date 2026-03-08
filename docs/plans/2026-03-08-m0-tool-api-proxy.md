# M0: Tool API Proxy + Discovery — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust proxy that injects credentials into tool API requests and provides a discovery endpoint, so AI agents never see API keys.

**Architecture:** Single-binary axum server. YAML config defines tools with upstream URLs and credentials (env var expansion). Requests to `/api/{tool}/{path}` get auth headers stripped and replaced with configured credentials, then forwarded upstream (optionally through Pipelock egress proxy). `GET /tools` and `GET /health` provide discovery and monitoring.

**Tech Stack:** Rust 2024 edition, tokio, axum 0.8, reqwest 0.12 (with proxy support), serde + serde_yaml, secrecy 0.10 (SecretString), tracing + tracing-subscriber (JSON), clap 4, opentelemetry + opentelemetry-otlp (optional feature)

**Reference:** `SPEC.md` sections: M0 scope, Config Format, API Reference, Build + Release

---

### Task 1: Project Scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `.gitignore`
- Create: `config.example.yaml`

**Step 1: Create Cargo.toml with all dependencies**

```toml
[package]
name = "secure-agent-proxy"
version = "0.1.0"
edition = "2024"
description = "Secure proxy for AI agent tool access with credential injection"
license = "Apache-2.0"

[[bin]]
name = "sap"
path = "src/main.rs"

[dependencies]
axum = "0.8"
clap = { version = "4", features = ["derive"] }
hyper = { version = "1", features = ["full"] }
http-body-util = "0.1"
reqwest = { version = "0.12", features = ["json", "stream"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
secrecy = { version = "0.10", features = ["serde"] }
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["trace", "cors"] }

[dev-dependencies]
axum-test = "16"
wiremock = "0.6"
tokio-test = "0.4"
```

**Step 2: Create minimal main.rs**

```rust
use std::process::ExitCode;

fn main() -> ExitCode {
    println!("sap: secure-agent-proxy");
    ExitCode::SUCCESS
}
```

**Step 3: Create .gitignore**

```
/target
*.swp
*.swo
.DS_Store
```

**Step 4: Create config.example.yaml**

Copy the Config Format section from SPEC.md (lines 232-320) into this file.

**Step 5: Verify it compiles**

Run: `cd /Users/jxstanford/devel/openclaw-repos/secure-agent-proxy && cargo build`
Expected: Compiles successfully, produces `target/debug/sap`

**Step 6: Run the binary**

Run: `cargo run`
Expected: Prints "sap: secure-agent-proxy"

**Step 7: Commit**

```bash
git add Cargo.toml src/main.rs .gitignore config.example.yaml docs/
git commit -m "Scaffold project with dependencies and example config"
```

---

### Task 2: Config Parsing

**Files:**
- Create: `src/config.rs`
- Create: `tests/config_test.rs`
- Modify: `src/main.rs`

**Step 1: Write the failing test**

Create `tests/config_test.rs`:

```rust
use secure_agent_proxy::config::AppConfig;

#[test]
fn test_parse_minimal_config() {
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
      value: "Bearer test-token-123"
    timeout_seconds: 30
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.listen.port, 9200);
    assert_eq!(config.tools.len(), 1);
    assert_eq!(config.tools[0].name, "github");
    assert_eq!(config.tools[0].upstream, "https://api.github.com");
    assert!(config.tools[0].cloud);
}

#[test]
fn test_empty_tools_list() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.tools.is_empty());
}

#[test]
fn test_optional_fields_default() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.egress_proxy.is_none());
    assert!(config.inbound_auth.is_none());
    assert!(config.telemetry.is_none());
    assert!(config.logging.is_none());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test config_test`
Expected: FAIL — `config` module doesn't exist

**Step 3: Write config module**

Create `src/config.rs`:

```rust
use secrecy::SecretString;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub listen: ListenConfig,
    pub inbound_auth: Option<InboundAuthConfig>,
    pub egress_proxy: Option<String>,
    pub telemetry: Option<TelemetryConfig>,
    pub logging: Option<LoggingConfig>,
    #[serde(default)]
    pub tools: Vec<ToolConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    9200
}

#[derive(Debug, Deserialize)]
pub struct InboundAuthConfig {
    pub mode: String,
    pub token: Option<SecretString>,
}

#[derive(Debug, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    pub otlp_endpoint: Option<String>,
    pub service_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    pub file: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ToolConfig {
    pub name: String,
    pub description: String,
    pub upstream: String,
    #[serde(default)]
    pub cloud: bool,
    pub auth: Option<ToolAuthConfig>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Debug, Deserialize)]
pub struct ToolAuthConfig {
    pub header: String,
    pub value: SecretString,
}
```

Update `src/main.rs` to export the module:

```rust
pub mod config;

use std::process::ExitCode;

fn main() -> ExitCode {
    println!("sap: secure-agent-proxy");
    ExitCode::SUCCESS
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --test config_test`
Expected: 3 tests PASS

**Step 5: Commit**

```bash
git add src/config.rs src/main.rs tests/config_test.rs
git commit -m "Add config parsing with YAML deserialization and SecretString"
```

---

### Task 3: Environment Variable Expansion

**Files:**
- Modify: `src/config.rs`
- Create: `tests/env_expansion_test.rs`

**Step 1: Write the failing test**

Create `tests/env_expansion_test.rs`:

```rust
use secure_agent_proxy::config::expand_env_vars;

#[test]
fn test_expand_single_var() {
    std::env::set_var("TEST_SAP_TOKEN", "secret123");
    let result = expand_env_vars("Bearer ${TEST_SAP_TOKEN}");
    assert_eq!(result, "Bearer secret123");
    std::env::remove_var("TEST_SAP_TOKEN");
}

#[test]
fn test_expand_missing_var_empty() {
    let result = expand_env_vars("Bearer ${NONEXISTENT_VAR_12345}");
    assert_eq!(result, "Bearer ");
}

#[test]
fn test_no_vars_passthrough() {
    let result = expand_env_vars("plain-value");
    assert_eq!(result, "plain-value");
}

#[test]
fn test_expand_multiple_vars() {
    std::env::set_var("TEST_SAP_A", "aaa");
    std::env::set_var("TEST_SAP_B", "bbb");
    let result = expand_env_vars("${TEST_SAP_A}-${TEST_SAP_B}");
    assert_eq!(result, "aaa-bbb");
    std::env::remove_var("TEST_SAP_A");
    std::env::remove_var("TEST_SAP_B");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test env_expansion_test`
Expected: FAIL — `expand_env_vars` doesn't exist

**Step 3: Implement expand_env_vars in config.rs**

Add to `src/config.rs`:

```rust
use std::env;

/// Expand `${VAR_NAME}` patterns in a string using environment variables.
/// Missing variables expand to empty string.
pub fn expand_env_vars(input: &str) -> String {
    let mut result = input.to_string();
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let value = env::var(var_name).unwrap_or_default();
            result = format!("{}{}{}", &result[..start], value, &result[start + end + 1..]);
        } else {
            break;
        }
    }
    result
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --test env_expansion_test`
Expected: 4 tests PASS

**Step 5: Add config loading function with env expansion**

Add to `src/config.rs`:

```rust
use std::path::Path;

/// Load config from YAML file, expanding `${VAR}` patterns in the raw YAML
/// before parsing. This ensures SecretString fields get the resolved values.
pub fn load_config(path: &Path) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let expanded = expand_env_vars(&raw);
    let config: AppConfig = serde_yaml::from_str(&expanded)?;
    Ok(config)
}
```

**Step 6: Run all tests**

Run: `cargo test`
Expected: All tests PASS

**Step 7: Commit**

```bash
git add src/config.rs tests/env_expansion_test.rs
git commit -m "Add environment variable expansion for config values"
```

---

### Task 4: Conditional Tool Activation

**Files:**
- Modify: `src/config.rs`
- Create: `tests/tool_activation_test.rs`

**Step 1: Write the failing test**

Create `tests/tool_activation_test.rs`:

```rust
use secure_agent_proxy::config::AppConfig;

#[test]
fn test_active_tools_filters_empty_credentials() {
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
      value: "Bearer real-token"
    timeout_seconds: 30
  - name: "tavily"
    description: "Tavily"
    upstream: "https://api.tavily.com"
    auth:
      header: "x-api-key"
      value: ""
    timeout_seconds: 15
  - name: "noauth"
    description: "No auth tool"
    upstream: "https://example.com"
    timeout_seconds: 10
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let active = config.active_tools();
    // github has a real token — active
    // tavily has empty token — filtered out
    // noauth has no auth block — active (no credentials needed)
    assert_eq!(active.len(), 2);
    assert_eq!(active[0].name, "github");
    assert_eq!(active[1].name, "noauth");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test tool_activation_test`
Expected: FAIL — `active_tools()` method doesn't exist

**Step 3: Implement active_tools**

Add to `src/config.rs` in `impl AppConfig`:

```rust
use secrecy::ExposeSecret;

impl AppConfig {
    /// Return tools that are active (have valid credentials or no auth required).
    /// Tools with an auth block but empty value are considered unconfigured.
    pub fn active_tools(&self) -> Vec<&ToolConfig> {
        self.tools
            .iter()
            .filter(|t| match &t.auth {
                Some(auth) => !auth.value.expose_secret().is_empty(),
                None => true, // no auth required
            })
            .collect()
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --test tool_activation_test`
Expected: PASS

**Step 5: Commit**

```bash
git add src/config.rs tests/tool_activation_test.rs
git commit -m "Add conditional tool activation filtering empty credentials"
```

---

### Task 5: App State and Server Startup

**Files:**
- Create: `src/app.rs`
- Modify: `src/main.rs`
- Create: `tests/health_test.rs`

**Step 1: Write the failing test for /health**

Create `tests/health_test.rs`:

```rust
use axum_test::TestServer;
use secure_agent_proxy::app::build_app;
use secure_agent_proxy::config::AppConfig;

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
    let server = TestServer::new(app).unwrap();

    let resp = server.get("/health").await;
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
    let server = TestServer::new(app).unwrap();

    let resp = server.get("/health").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["tools"].as_array().unwrap().len(), 0);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test health_test`
Expected: FAIL — `app` module doesn't exist

**Step 3: Implement app module with health endpoint**

Create `src/app.rs`:

```rust
use axum::{Router, Json, extract::State};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

use crate::config::AppConfig;

pub struct AppState {
    pub config: AppConfig,
    pub started_at: Instant,
}

pub fn build_app(config: AppConfig) -> Router {
    let tool_names: Vec<String> = config
        .active_tools()
        .iter()
        .map(|t| t.name.clone())
        .collect();

    let state = Arc::new(AppState {
        config,
        started_at: Instant::now(),
    });

    Router::new()
        .route("/health", axum::routing::get(health_handler))
        .with_state(state)
}

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let tool_names: Vec<String> = state
        .config
        .active_tools()
        .iter()
        .map(|t| t.name.clone())
        .collect();

    Json(json!({
        "status": "ok",
        "uptime_seconds": state.started_at.elapsed().as_secs(),
        "tools": tool_names,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
```

Update `src/main.rs`:

```rust
pub mod app;
pub mod config;

use std::process::ExitCode;

fn main() -> ExitCode {
    println!("sap: secure-agent-proxy");
    ExitCode::SUCCESS
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --test health_test`
Expected: 2 tests PASS

**Step 5: Commit**

```bash
git add src/app.rs src/main.rs tests/health_test.rs
git commit -m "Add app state and /health endpoint"
```

---

### Task 6: Tool Discovery Endpoint

**Files:**
- Modify: `src/app.rs`
- Create: `tests/discovery_test.rs`

**Step 1: Write the failing test**

Create `tests/discovery_test.rs`:

```rust
use axum_test::TestServer;
use secure_agent_proxy::app::build_app;
use secure_agent_proxy::config::AppConfig;

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
    let server = TestServer::new(app).unwrap();

    let resp = server.get("/tools").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    let tools = body["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1); // tavily filtered out (empty key)
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
    let server = TestServer::new(app).unwrap();

    let resp = server.get("/tools").await;
    let body_str = resp.text();
    assert!(!body_str.contains("super-secret-token"));
    assert!(!body_str.contains("Bearer"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test discovery_test`
Expected: FAIL — no `/tools` route

**Step 3: Add tools discovery handler to app.rs**

Add route and handler in `src/app.rs`:

```rust
// In build_app, add route:
.route("/tools", axum::routing::get(tools_handler))

// New handler:
async fn tools_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let tools: Vec<Value> = state
        .config
        .active_tools()
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "type": "api",
                "path": format!("/api/{}", t.name),
                "description": t.description,
            })
        })
        .collect();

    Json(json!({ "tools": tools }))
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test --test discovery_test`
Expected: 2 tests PASS

**Step 5: Commit**

```bash
git add src/app.rs tests/discovery_test.rs
git commit -m "Add GET /tools discovery endpoint"
```

---

### Task 7: Proxy Handler — Credential Injection + Forwarding

**Files:**
- Create: `src/proxy.rs`
- Modify: `src/app.rs`
- Create: `tests/proxy_test.rs`

**Step 1: Write the failing test**

Create `tests/proxy_test.rs`:

```rust
use axum_test::TestServer;
use secure_agent_proxy::app::build_app;
use secure_agent_proxy::config::AppConfig;
use wiremock::matchers::{method, path, header};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_proxy_injects_credentials() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/test"))
        .and(header("Authorization", "Bearer injected-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"id": 1, "name": "test-repo"})
        ))
        .mount(&mock)
        .await;

    let yaml = format!(r#"
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
"#, mock.uri());

    let config: AppConfig = serde_yaml::from_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app).unwrap();

    let resp = server.get("/api/github/repos/test").await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["name"], "test-repo");
}

#[tokio::test]
async fn test_proxy_strips_agent_auth_header() {
    let mock = MockServer::start().await;

    // The mock expects the INJECTED header, not the agent's
    Mock::given(method("GET"))
        .and(path("/test"))
        .and(header("Authorization", "Bearer injected"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let yaml = format!(r#"
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
"#, mock.uri());

    let config: AppConfig = serde_yaml::from_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app).unwrap();

    // Agent sends its own Authorization header — should be stripped
    let resp = server
        .get("/api/svc/test")
        .add_header("Authorization".parse().unwrap(), "Bearer agent-token".parse().unwrap())
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn test_proxy_unknown_tool_404() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app).unwrap();

    let resp = server.get("/api/unknown/test").await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json();
    assert!(body["error"]["message"].as_str().unwrap().contains("Unknown tool"));
}

#[tokio::test]
async fn test_proxy_post_with_body() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("x-api-key", "tavily-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"results": []})
        ))
        .mount(&mock)
        .await;

    let yaml = format!(r#"
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
"#, mock.uri());

    let config: AppConfig = serde_yaml::from_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app).unwrap();

    let resp = server
        .post("/api/tavily/v1/search")
        .json(&serde_json::json!({"query": "test"}))
        .await;
    resp.assert_status_ok();
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test proxy_test`
Expected: FAIL — no `/api` route, no proxy module

**Step 3: Implement proxy module**

Create `src/proxy.rs`:

```rust
use axum::{
    body::Body,
    extract::{Path, State, Request},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use reqwest::Client;
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

use crate::app::AppState;
use crate::config::ToolConfig;

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path((tool_name, path)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    // Find the tool
    let tool = match state.config.active_tools().into_iter().find(|t| t.name == tool_name) {
        Some(t) => t,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": {
                        "message": format!("Unknown tool: {}", tool_name),
                        "type": "not_found"
                    }
                })),
            ).into_response();
        }
    };

    let upstream_url = format!("{}/{}", tool.upstream.trim_end_matches('/'), path);
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": {"message": "Failed to read request body", "type": "bad_request"}})),
            ).into_response();
        }
    };

    // Build upstream request
    let client = build_client(tool, &state);
    let mut upstream_req = client.request(method, &upstream_url);

    // Forward headers, stripping auth-related ones
    let auth_header_name = tool.auth.as_ref().map(|a| a.header.to_lowercase());
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_lowercase();
        // Strip agent-sent auth headers and hop-by-hop headers
        if lower == "host"
            || lower == "authorization"
            || lower == "x-api-key"
            || auth_header_name.as_deref() == Some(&lower)
        {
            continue;
        }
        upstream_req = upstream_req.header(name, value);
    }

    // Inject configured credentials
    if let Some(auth) = &tool.auth {
        upstream_req = upstream_req.header(&auth.header, auth.value.expose_secret().as_str());
    }

    // Forward body
    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes);
    }

    // Send
    match upstream_req.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response_headers = HeaderMap::new();
            for (name, value) in resp.headers() {
                if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
                    response_headers.insert(name.clone(), v);
                }
            }
            let body = resp.bytes().await.unwrap_or_default();
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = status;
            *response.headers_mut() = response_headers;
            response
        }
        Err(e) => {
            if e.is_timeout() {
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(json!({"error": {"message": "Upstream timeout", "type": "timeout"}})),
                ).into_response()
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": {"message": "Upstream error", "type": "upstream_error"}})),
                ).into_response()
            }
        }
    }
}

fn build_client(tool: &ToolConfig, state: &AppState) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(tool.timeout_seconds));

    // Route through egress proxy for cloud-bound requests
    if tool.cloud {
        if let Some(proxy_url) = &state.config.egress_proxy {
            if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
                builder = builder.proxy(proxy);
            }
        }
    }

    builder.build().unwrap_or_else(|_| Client::new())
}
```

**Step 4: Wire proxy into app.rs**

Update `src/app.rs` to add the proxy route:

```rust
use crate::proxy;

// In build_app, add:
.route("/api/{tool_name}/{*path}", axum::routing::any(proxy::proxy_handler))
```

Update `src/main.rs`:

```rust
pub mod app;
pub mod config;
pub mod proxy;
```

**Step 5: Run test to verify it passes**

Run: `cargo test --test proxy_test`
Expected: 4 tests PASS

**Step 6: Commit**

```bash
git add src/proxy.rs src/app.rs src/main.rs tests/proxy_test.rs
git commit -m "Add proxy handler with credential injection and upstream forwarding"
```

---

### Task 8: Inbound Auth Middleware

**Files:**
- Create: `src/auth.rs`
- Modify: `src/app.rs`
- Create: `tests/auth_test.rs`

**Step 1: Write the failing test**

Create `tests/auth_test.rs`:

```rust
use axum_test::TestServer;
use secure_agent_proxy::app::build_app;
use secure_agent_proxy::config::AppConfig;

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
    let server = TestServer::new(app).unwrap();

    let resp = server.get("/health").await;
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
    let server = TestServer::new(app).unwrap();

    let resp = server.get("/tools").await;
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
    let server = TestServer::new(app).unwrap();

    let resp = server
        .get("/tools")
        .add_header("Authorization".parse().unwrap(), "Bearer wrong-token".parse().unwrap())
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
    let server = TestServer::new(app).unwrap();

    let resp = server
        .get("/tools")
        .add_header("Authorization".parse().unwrap(), "Bearer my-secret-token".parse().unwrap())
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
    let server = TestServer::new(app).unwrap();

    // Health should work without auth (for load balancer probes)
    let resp = server.get("/health").await;
    resp.assert_status_ok();
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test auth_test`
Expected: FAIL — auth not enforced

**Step 3: Implement auth middleware**

Create `src/auth.rs`:

```rust
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::Arc;

use crate::app::AppState;

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    // Skip auth for /health
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }

    let auth_config = match &state.config.inbound_auth {
        Some(auth) if auth.mode == "bearer" => auth,
        _ => return next.run(req).await, // no auth configured or mode = "none"
    };

    let expected_token = match &auth_config.token {
        Some(t) => t,
        None => return next.run(req).await,
    };

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let provided_token = auth_header.and_then(|h| h.strip_prefix("Bearer "));

    match provided_token {
        Some(token) if token == expected_token.expose_secret().as_str() => {
            next.run(req).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"message": "Unauthorized", "type": "auth_error"}})),
        ).into_response(),
    }
}
```

Update `src/app.rs` to apply the middleware:

```rust
use axum::middleware;
use crate::auth;

// In build_app, wrap routes with auth middleware:
// .layer(middleware::from_fn_with_state(state.clone(), auth::auth_middleware))
```

Update `src/main.rs`:

```rust
pub mod app;
pub mod auth;
pub mod config;
pub mod proxy;
```

**Step 4: Run test to verify it passes**

Run: `cargo test --test auth_test`
Expected: 5 tests PASS

**Step 5: Commit**

```bash
git add src/auth.rs src/app.rs src/main.rs tests/auth_test.rs
git commit -m "Add optional inbound bearer token auth middleware"
```

---

### Task 9: Structured Logging

**Files:**
- Create: `src/telemetry.rs`
- Modify: `src/main.rs`
- Modify: `src/app.rs`

**Step 1: Implement telemetry module**

Create `src/telemetry.rs`:

```rust
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::LoggingConfig;

pub fn init_logging(config: Option<&LoggingConfig>) {
    let level = config
        .map(|c| c.level.as_str())
        .unwrap_or("info");

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json().with_target(true))
        .init();
}
```

**Step 2: Add request tracing to app.rs**

```rust
use tower_http::trace::TraceLayer;

// In build_app, add:
.layer(TraceLayer::new_for_http())
```

**Step 3: Update main.rs with full async entrypoint**

```rust
pub mod app;
pub mod auth;
pub mod config;
pub mod proxy;
pub mod telemetry;

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser)]
#[command(name = "sap", about = "Secure Agent Proxy")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/sap/config.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let config = config::load_config(&cli.config).unwrap_or_else(|e| {
        eprintln!("Failed to load config from {}: {}", cli.config.display(), e);
        std::process::exit(1);
    });

    telemetry::init_logging(config.logging.as_ref());

    let addr = SocketAddr::new(
        config.listen.host.parse().unwrap_or([127, 0, 0, 1].into()),
        config.listen.port,
    );

    info!(
        listen = %addr,
        tools = config.active_tools().len(),
        "Starting secure-agent-proxy"
    );

    let app = app::build_app(config);
    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        eprintln!("Failed to bind to {}: {}", addr, e);
        std::process::exit(1);
    });

    info!("Listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}
```

**Step 4: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully

**Step 5: Run all tests**

Run: `cargo test`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add src/telemetry.rs src/main.rs src/app.rs
git commit -m "Add structured JSON logging and CLI entrypoint"
```

---

### Task 10: SIGHUP Config Reload

**Files:**
- Modify: `src/main.rs`
- Modify: `src/app.rs`

**Step 1: Make AppState config reloadable**

Update `src/app.rs` to use `ArcSwap` for hot-reloadable config:

Add to `Cargo.toml`:
```toml
arc-swap = "1"
```

Update `AppState`:

```rust
use arc_swap::ArcSwap;

pub struct AppState {
    pub config: ArcSwap<AppConfig>,
    pub started_at: Instant,
}
```

Update all handlers to use `state.config.load()` instead of `state.config` directly.

**Step 2: Add SIGHUP handler to main.rs**

```rust
use tokio::signal::unix::{signal, SignalKind};

// After server starts, spawn reload listener:
let state_for_reload = state.clone();
let config_path = cli.config.clone();
tokio::spawn(async move {
    let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
    loop {
        sighup.recv().await;
        info!("SIGHUP received, reloading config");
        match config::load_config(&config_path) {
            Ok(new_config) => {
                let tool_count = new_config.active_tools().len();
                state_for_reload.config.store(Arc::new(new_config));
                info!(tools = tool_count, "Config reloaded successfully");
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to reload config, keeping current");
            }
        }
    }
});
```

**Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully

**Step 4: Run all tests**

Run: `cargo test`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add Cargo.toml src/main.rs src/app.rs
git commit -m "Add SIGHUP config hot-reload with ArcSwap"
```

---

### Task 11: Integration Test — Full Proxy Flow

**Files:**
- Create: `tests/integration_test.rs`

**Step 1: Write full flow integration test**

Create `tests/integration_test.rs`:

```rust
use axum_test::TestServer;
use secure_agent_proxy::app::build_app;
use secure_agent_proxy::config::AppConfig;
use wiremock::matchers::{method, path, header};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_full_proxy_flow() {
    // Start mock upstream
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("x-api-key", "real-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"results": [{"title": "test"}]}))
        )
        .mount(&mock)
        .await;

    let yaml = format!(r#"
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
"#, mock.uri());

    let config: AppConfig = serde_yaml::from_str(&yaml).unwrap();
    let app = build_app(config);
    let server = TestServer::new(app).unwrap();

    // 1. Health works without auth
    let resp = server.get("/health").await;
    resp.assert_status_ok();
    let health: serde_json::Value = resp.json();
    assert_eq!(health["tools"][0], "tavily");

    // 2. Discovery requires auth
    let resp = server.get("/tools").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);

    // 3. Discovery works with correct auth
    let resp = server
        .get("/tools")
        .add_header("Authorization".parse().unwrap(), "Bearer agent-token".parse().unwrap())
        .await;
    resp.assert_status_ok();

    // 4. Proxy injects credentials
    let resp = server
        .post("/api/tavily/v1/search")
        .add_header("Authorization".parse().unwrap(), "Bearer agent-token".parse().unwrap())
        .json(&serde_json::json!({"query": "rust proxy"}))
        .await;
    resp.assert_status_ok();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["results"][0]["title"], "test");

    // 5. Unknown tool returns 404
    let resp = server
        .get("/api/unknown/test")
        .add_header("Authorization".parse().unwrap(), "Bearer agent-token".parse().unwrap())
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}
```

**Step 2: Run test to verify it passes**

Run: `cargo test --test integration_test`
Expected: PASS

**Step 3: Run all tests**

Run: `cargo test`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add tests/integration_test.rs
git commit -m "Add full-flow integration test"
```

---

### Task 12: Final Polish + CI Config

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `LICENSE`

**Step 1: Create CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --all
      - run: cargo clippy -- -D warnings
      - run: cargo fmt --check

  build:
    runs-on: ubuntu-latest
    needs: test
    strategy:
      matrix:
        target: [x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - uses: Swatinem/rust-cache@v2
      - name: Install cross-compilation tools
        if: matrix.target == 'aarch64-unknown-linux-gnu'
        run: |
          sudo apt-get update
          sudo apt-get install -y gcc-aarch64-linux-gnu
      - run: cargo build --release --target ${{ matrix.target }}
        env:
          CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER: aarch64-linux-gnu-gcc
```

**Step 2: Create LICENSE**

Create `LICENSE` with Apache-2.0 text (standard template).

**Step 3: Run full test suite one final time**

Run: `cargo test && cargo clippy -- -D warnings && cargo fmt --check`
Expected: All pass

**Step 4: Commit**

```bash
git add .github/ LICENSE
git commit -m "Add CI workflow and Apache-2.0 license"
```

---

## Summary

| Task | What | Tests |
|------|------|-------|
| 1 | Project scaffold | Compile check |
| 2 | Config parsing | 3 tests |
| 3 | Env var expansion | 4 tests |
| 4 | Conditional tool activation | 1 test |
| 5 | App state + /health | 2 tests |
| 6 | GET /tools discovery | 2 tests |
| 7 | Proxy handler + credential injection | 4 tests |
| 8 | Inbound auth middleware | 5 tests |
| 9 | Structured logging + CLI | Compile check |
| 10 | SIGHUP reload | Compile check |
| 11 | Integration test | 1 test (full flow) |
| 12 | CI + license | CI config |

**Total: 22+ tests, 12 commits, ~6 files**
