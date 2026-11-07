//! Listener startup failures surface immediately (AGENT-217).
//!
//! Before the fix the admin UDS and admin HTTPS listeners bound inside
//! spawned tasks whose results were only joined after the shutdown
//! signal. A daemon whose admin surface could not start kept serving
//! agents, logged nothing, and reported the error only when stopped.

use agent_locksmith::config::parse_config_str;
use agent_locksmith::{argon2_helper, daemon, token};
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

/// A failing daemon must return on its own, well before anyone stops it.
const STARTUP_FAILURE_DEADLINE: Duration = Duration::from_secs(5);

fn write_operators(dir: &Path) -> std::path::PathBuf {
    let ops_path = dir.join("operators.yaml");
    let op_tok = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_tok.secret.expose().to_string(),
    ))
    .unwrap();
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_tok.public_id.as_str(),
            op_hash
        ),
    )
    .unwrap();
    ops_path
}

fn admin_yaml(dir: &Path, socket: &Path, extra_listen: &str) -> String {
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 0
  admin_socket:
    path: "{sock}"
{extra_listen}
shutdown:
  drain_window_seconds: 2
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools: []
"#,
        sock = socket.display(),
        ops = write_operators(dir).display(),
        db = dir.join("locksmith.db").display(),
    )
}

async fn exit_without_shutdown(yaml: &str) -> String {
    let cfg = parse_config_str(yaml).unwrap();
    // The test never triggers shutdown: the daemon must stop by itself.
    let (_coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(2)).await;
    let result = timeout(STARTUP_FAILURE_DEADLINE, handle)
        .await
        .expect("daemon must stop on its own when a listener cannot start")
        .expect("daemon task must not panic");
    format!("{}", result.expect_err("listener failure must be an error"))
}

#[tokio::test]
async fn admin_socket_bind_failure_fails_startup() {
    let dir = TempDir::new().unwrap();
    // The socket's parent is a regular file, so the UDS cannot be created.
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, b"").unwrap();
    let socket = blocker.join("admin.sock");

    let msg = exit_without_shutdown(&admin_yaml(dir.path(), &socket, "")).await;
    assert!(
        msg.contains("admin listener"),
        "error names the admin listener; got: {msg}"
    );
}

#[tokio::test]
async fn admin_https_tls_failure_stops_daemon_before_shutdown() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("admin.sock");
    // TLS material is loaded inside the serving task, after the bind
    // succeeds: the listener stops early and the daemon must notice.
    let https = format!(
        r#"  admin_https:
    enabled: true
    host: "127.0.0.1"
    port: 0
    cert_path: "{cert}"
    key_path: "{key}""#,
        cert = dir.path().join("missing.crt").display(),
        key = dir.path().join("missing.key").display(),
    );

    let msg = exit_without_shutdown(&admin_yaml(dir.path(), &socket, &https)).await;
    assert!(
        msg.contains("admin HTTPS listener"),
        "error names the admin HTTPS listener; got: {msg}"
    );
}

#[tokio::test]
async fn start_reports_os_assigned_addresses() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("admin.sock");
    let cfg = parse_config_str(&admin_yaml(dir.path(), &socket, "")).unwrap();

    let started = daemon::start_with_drain_window(cfg, Duration::from_secs(2))
        .await
        .expect("daemon starts");
    assert_ne!(
        started.addrs.agent.port(),
        0,
        "port 0 resolves to a real port"
    );
    assert_eq!(started.addrs.admin_https, None, "admin HTTPS is off");
    assert!(
        socket.exists(),
        "admin socket is bound before start returns"
    );

    let livez = format!("http://{}/livez", started.addrs.agent);
    let resp = reqwest::get(&livez).await.expect("livez reachable");
    assert!(resp.status().is_success());

    started.coord.trigger();
    timeout(Duration::from_secs(4), started.handle)
        .await
        .expect("daemon exits")
        .expect("join ok")
        .expect("clean shutdown");
}

#[tokio::test]
async fn start_returns_the_startup_error() {
    let dir = TempDir::new().unwrap();
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, b"").unwrap();
    let cfg = parse_config_str(&admin_yaml(dir.path(), &blocker.join("admin.sock"), "")).unwrap();

    let err = timeout(
        STARTUP_FAILURE_DEADLINE,
        daemon::start_with_drain_window(cfg, Duration::from_secs(2)),
    )
    .await
    .expect("start returns promptly")
    .err()
    .expect("start fails");
    assert!(format!("{err}").contains("admin listener"), "got: {err}");
}
