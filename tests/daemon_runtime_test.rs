//! Daemon runtime integration test (M2 wiring).
//!
//! Covers: `daemon::run` brings up the agent TCP listener and the admin
//! UDS listener concurrently, both observe the same shutdown signal, and
//! both drain cleanly within the configured window.
//!
//! This is the M2 acceptance test for the wiring layer; UC end-to-end
//! flows through the CLI are covered separately by the cli e2e test.

use agent_locksmith::config::parse_config_str;
use agent_locksmith::{argon2_helper, daemon, token};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

/// Pick an unused TCP port by binding to :0, reading the port, and
/// dropping the listener. Race-prone in theory, fine in practice for
/// test isolation.
fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct DaemonFixture {
    dir: TempDir,
    socket_path: std::path::PathBuf,
    tcp_port: u16,
    op_token_wire: String,
}

fn build_fixture() -> DaemonFixture {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("admin.sock");
    let ops_path = dir.path().join("operators.yaml");
    let tcp_port = pick_port();

    let op_tok = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_token_wire = op_tok.wire_format();
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

    DaemonFixture {
        dir,
        socket_path,
        tcp_port,
        op_token_wire,
    }
}

fn config_yaml(f: &DaemonFixture) -> String {
    let db_path = f.dir.path().join("locksmith.db");
    let ops_path = f.dir.path().join("operators.yaml");
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {port}
  admin_socket:
    path: "{sock}"
shutdown:
  drain_window_seconds: 5
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools: []
"#,
        port = f.tcp_port,
        sock = f.socket_path.display(),
        ops = ops_path.display(),
        db = db_path.display(),
    )
}

#[tokio::test]
async fn daemon_binds_both_listeners_and_drains_clean() {
    let f = build_fixture();
    let cfg = parse_config_str(&config_yaml(&f)).unwrap();

    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;

    // Wait for both listeners to come up. The agent listener is a TCP
    // bind; the admin UDS listener is a unix socket. Poll the socket
    // file (its presence + 0660 mode prove bind_and_serve completed
    // setup). Cap at 2s.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !f.socket_path.exists() {
        if std::time::Instant::now() > deadline {
            panic!("admin UDS never appeared at {}", f.socket_path.display());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let perms = std::fs::metadata(&f.socket_path).unwrap().permissions();
    assert_eq!(
        perms.mode() & 0o777,
        0o660,
        "admin UDS must be mode 0660 (D-2)"
    );

    // Agent listener is up: a quick TCP probe to /livez returns 200.
    let agent_url = format!("http://127.0.0.1:{}/livez", f.tcp_port);
    let resp = reqwest::get(&agent_url).await.expect("livez reachable");
    assert!(resp.status().is_success(), "agent listener serving /livez");

    // Trigger shutdown; the daemon must complete within the drain
    // window.
    coord.trigger();
    let exit = timeout(Duration::from_secs(6), handle)
        .await
        .expect("daemon exits within 6s")
        .expect("join handle ok");
    exit.expect("daemon Ok(())");

    // Black-box token check (operator-side existence — the live
    // listener path is exercised in the CLI e2e test).
    assert!(f.op_token_wire.starts_with("lkop_"));
}

#[tokio::test]
async fn daemon_runs_without_admin_substrate() {
    // M0/M1 backward-compat: admin_socket absent ⇒ admin UDS not bound,
    // database not opened, operators.yaml not consulted.
    let port = pick_port();
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {port}
shutdown:
  drain_window_seconds: 2
tools: []
"#
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(2)).await;

    // Probe livez on the TCP listener.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if reqwest::get(format!("http://127.0.0.1:{port}/livez"))
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("agent listener never bound");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    coord.trigger();
    timeout(Duration::from_secs(3), handle)
        .await
        .expect("daemon exits within 3s")
        .expect("join handle ok")
        .expect("daemon Ok(())");
}

#[tokio::test]
async fn daemon_rejects_admin_socket_without_database() {
    let f = build_fixture();
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {port}
  admin_socket:
    path: "{sock}"
operator_credentials_path: "{ops}"
tools: []
"#,
        port = f.tcp_port,
        sock = f.socket_path.display(),
        ops = f.dir.path().join("operators.yaml").display(),
    );
    let cfg = parse_config_str(&yaml).unwrap();

    let coord = agent_locksmith::shutdown::ShutdownCoordinator::new(Duration::from_secs(2));
    let result = daemon::run(cfg, coord).await;
    let err = result.expect_err("daemon must refuse: admin without database");
    let msg = format!("{err}");
    assert!(
        msg.contains("database"),
        "error names the missing field; got: {msg}"
    );
}
