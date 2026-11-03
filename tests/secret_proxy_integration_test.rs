//! M5 file custody with D1 explicit owner upgrade: legacy file cache alone
//! cannot authorize dispatch. Import the real resolver's synthetic bytes through
//! the existing stored credential API and explicitly select that snapshot.
#[path = "support/file_sealed_upgrade.rs"]
mod upgrade;

use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::{argon2_helper, daemon, token};
use secrecy::ExposeSecret;
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

fn write_operators_yaml(p: &std::path::Path) -> String {
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
    format!("Bearer {}", op_tok.wire_format())
}

/// Pre-register an agent in the database before the daemon opens it.
/// M9: admin substrate enabled implies per-agent bearer auth on the
/// proxy hot path, so daemon-driven tests need a real lk_ token to
/// reach `/api/...` endpoints. Omitted grants authorize no tools.
async fn pre_register_agent(db: &std::path::Path, name: &str) -> String {
    let pool = open_and_migrate(db).await.expect("migrate");
    let agents = AgentRepository::new(pool.clone());
    let (pid, secret) = agents
        .create(name, None, None, None, None, None)
        .await
        .expect("agent insert");
    pool.close().await;
    format!("Bearer lk_{pid}.{}", secret.expose_secret())
}

#[tokio::test]
async fn file_sealed_owner_snapshot_import_requires_explicit_binding() {
    upgrade::enable_stored_source();
    let dir = TempDir::new().unwrap();

    // Step 1 — sealed file with chmod-0600.
    let sealed_path = dir.path().join("api_key");
    std::fs::write(&sealed_path, "Bearer s3cr3t").unwrap();
    std::fs::set_permissions(&sealed_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Operators + DB + sock.
    let sock = dir.path().join("admin.sock");
    let ops = dir.path().join("operators.yaml");
    let db = dir.path().join("locksmith.db");
    let operator = write_operators_yaml(&ops);

    // Mock upstream that asserts the credential header.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer s3cr3t"))
        .respond_with(ResponseTemplate::new(200).set_body_string("file-account-X"))
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
    // M9: admin substrate is enabled (admin_socket + database), so the
    // agent listener requires a per-agent bearer token. Pre-register
    // before the daemon opens the DB.
    let agent_bearer = pre_register_agent(&db, "ping-agent").await;

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

    let url = format!("http://127.0.0.1:{agent_port}/api/ping/v1/ping");
    // The real daemon resolved the legacy file at startup; that cached value
    // must not authorize an unbound caller or reach the upstream.
    upgrade::assert_denied(&url, &agent_bearer, &mock).await;
    upgrade::import_snapshot(&sock, &operator, &sealed_path, &mock.uri()).await;
    // This is a deliberate snapshot import, not an ongoing file-backed binding.
    std::fs::write(&sealed_path, "Bearer different-file-account").unwrap();
    let resp = reqwest::Client::new()
        .get(&url)
        .header("authorization", &agent_bearer)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert_eq!(resp.text().await.unwrap(), "file-account-X");
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
    upgrade::clear(&sock, &operator).await;
    upgrade::assert_denied(&url, &agent_bearer, &mock).await;

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
    // M9: admin substrate is enabled, so even discovery (`/tools`) is
    // gated by per-agent bearer auth. Pre-register before the daemon
    // opens the DB.
    let agent_bearer = pre_register_agent(&db, "discovery-agent").await;

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

    // Deliberately grant the now-configured authless entry.
    let pool = open_and_migrate(&db).await.unwrap();
    let agents = AgentRepository::new(pool.clone());
    let id = agents
        .get_by_name("discovery-agent")
        .await
        .unwrap()
        .unwrap()
        .public_id;
    agents
        .update_policy(&id, Some(Some(vec!["open".into()])), None, None, None)
        .await
        .unwrap();
    pool.close().await;

    // /tools must include the `open` tool (no auth) but NOT `broken`
    // (credential failed to resolve).
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{agent_port}/tools"))
        .header("authorization", &agent_bearer)
        .send()
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
