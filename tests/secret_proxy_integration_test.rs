//! M5 acceptance: a `from_file_sealed:` tool credential gets resolved
//! at daemon startup and injected on the proxy hot path.
//!
//! End-to-end shape:
//! 1. Write a chmod-0600 sealed file with the credential bytes.
//! 2. Start `daemon::run` with a config that references it via
//!    `from_file_sealed: { path: ... }`.
//! 3. Make a proxy request through the agent listener.
//! 4. Assert the upstream received the configured header value (proves
//!    the resolved credential reached the hot path).

use agent_locksmith::config::parse_config_str;
use agent_locksmith::{argon2_helper, daemon, token};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn write_operators_yaml(p: &std::path::Path) {
    let op_tok = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_tok.secret.expose().to_string(),
    ))
    .unwrap();
    std::fs::write(
        p,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_tok.public_id.as_str(),
            op_hash
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn from_file_sealed_credential_reaches_proxy_hot_path() {
    let dir = TempDir::new().unwrap();

    // Step 1 — sealed file with chmod-0600.
    let sealed_path = dir.path().join("api_key");
    std::fs::write(&sealed_path, "Bearer s3cr3t").unwrap();
    std::fs::set_permissions(&sealed_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Operators + DB + sock.
    let sock = dir.path().join("admin.sock");
    let ops = dir.path().join("operators.yaml");
    let db = dir.path().join("locksmith.db");
    write_operators_yaml(&ops);

    // Mock upstream that asserts the credential header.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer s3cr3t"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let agent_port = pick_port();
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {agent_port}
  admin_socket:
    path: "{sock}"
shutdown:
  drain_window_seconds: 5
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools:
  - name: "ping"
    description: "ping service"
    upstream: "{upstream}"
    auth:
      header: "authorization"
      value:
        from_file_sealed:
          path: "{sealed}"
"#,
        sock = sock.display(),
        ops = ops.display(),
        db = db.display(),
        upstream = mock.uri(),
        sealed = sealed_path.display(),
    );
    let cfg = parse_config_str(&yaml).expect("config parses");
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;

    // Wait for daemon to bind.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let livez = format!("http://127.0.0.1:{agent_port}/livez");
    while reqwest::get(&livez).await.is_err() {
        if std::time::Instant::now() > deadline {
            panic!("agent listener never bound");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Make a proxy request — wiremock asserts the header on its end.
    let resp = reqwest::get(format!("http://127.0.0.1:{agent_port}/api/ping/v1/ping"))
        .await
        .expect("proxy request reaches daemon");
    assert!(
        resp.status().is_success(),
        "expected 200, got {}",
        resp.status()
    );

    coord.trigger();
    timeout(Duration::from_secs(6), handle)
        .await
        .expect("daemon exits within 6s")
        .expect("join ok")
        .expect("daemon Ok(())");
}

#[tokio::test]
async fn missing_sealed_file_degrades_tool_quietly() {
    // INF-4 / Q-17 degraded mode: a single tool's credential failure
    // must not take the daemon down. The tool becomes inactive (its
    // /tools entry disappears, its proxy path 502s on missing creds)
    // but other tools and the admin surface keep working.
    let dir = TempDir::new().unwrap();
    let absent_sealed = dir.path().join("never_existed");
    let sock = dir.path().join("admin.sock");
    let ops = dir.path().join("operators.yaml");
    let db = dir.path().join("locksmith.db");
    write_operators_yaml(&ops);

    let agent_port = pick_port();
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {agent_port}
  admin_socket:
    path: "{sock}"
shutdown:
  drain_window_seconds: 5
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools:
  - name: "broken"
    description: "missing sealed file"
    upstream: "http://127.0.0.1:1"
    auth:
      header: "authorization"
      value:
        from_file_sealed:
          path: "{path}"
  - name: "open"
    description: "no auth"
    upstream: "http://127.0.0.1:1"
"#,
        sock = sock.display(),
        ops = ops.display(),
        db = db.display(),
        path = absent_sealed.display(),
    );
    let cfg = parse_config_str(&yaml).expect("config parses");
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;

    // Daemon must reach a serving state.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let livez = format!("http://127.0.0.1:{agent_port}/livez");
    while reqwest::get(&livez).await.is_err() {
        if std::time::Instant::now() > deadline {
            panic!("agent listener never bound");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // /tools must include the `open` tool (no auth) but NOT `broken`
    // (credential failed to resolve).
    let body: serde_json::Value = reqwest::get(format!("http://127.0.0.1:{agent_port}/tools"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = body["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"open"), "open tool active");
    assert!(
        !names.contains(&"broken"),
        "broken tool with missing sealed file is degraded; got names={names:?}"
    );

    coord.trigger();
    timeout(Duration::from_secs(6), handle)
        .await
        .expect("daemon exits within 6s")
        .expect("join ok")
        .expect("daemon Ok(())");
}
