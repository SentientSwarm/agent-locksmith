//! T4.3 — admin HTTPS listener is off by default.
//!
//! When `listen.admin_https` is absent or `enabled: false`, the daemon
//! must NOT bind the HTTPS port. The carve-out mirrors the admin UDS
//! pattern: opt-in via config, never bound by default.

use agent_locksmith::config::parse_config_str;
use agent_locksmith::{argon2_helper, daemon, token};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

/// Hold a port for the whole test instead of probing and releasing it,
/// which another process could take in between (AGENT-219). A daemon that
/// tried to bind a held port would fail startup.
fn hold_port() -> std::net::TcpListener {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    assert!(
        std::net::TcpListener::bind(("127.0.0.1", port)).is_err(),
        "a held port cannot be bound twice on this platform"
    );
    held
}

fn fixture_yaml(sock: &std::path::Path, ops: &std::path::Path, db: &std::path::Path) -> String {
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 0
  admin_socket:
    path: "{sock}"
shutdown:
  drain_window_seconds: 2
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools: []
"#,
        sock = sock.display(),
        ops = ops.display(),
        db = db.display(),
    )
}

fn write_operators_yaml(path: &std::path::Path) {
    let op_tok = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_tok.secret.expose().to_string(),
    ))
    .unwrap();
    std::fs::write(
        path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_tok.public_id.as_str(),
            op_hash
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn admin_https_not_bound_when_block_absent() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("admin.sock");
    let ops = dir.path().join("operators.yaml");
    let db = dir.path().join("locksmith.db");
    write_operators_yaml(&ops);

    let cfg = parse_config_str(&fixture_yaml(&sock, &ops, &db)).unwrap();
    let started = daemon::start_with_drain_window(cfg, Duration::from_secs(2))
        .await
        .expect("daemon starts");
    let (coord, handle) = (started.coord, started.handle);

    // Every listener is bound before start returns: none is admin HTTPS.
    assert_eq!(
        started.addrs.admin_https, None,
        "admin HTTPS must not be bound when the block is absent"
    );

    coord.trigger();
    timeout(Duration::from_secs(3), handle)
        .await
        .expect("daemon exits within 3s")
        .expect("join ok")
        .expect("daemon Ok(())");
}

#[tokio::test]
async fn admin_https_not_bound_when_enabled_false() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("admin.sock");
    let ops = dir.path().join("operators.yaml");
    let db = dir.path().join("locksmith.db");
    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");
    write_operators_yaml(&ops);
    // Touch cert/key so config loads cleanly even though enabled=false.
    std::fs::write(&cert, "").unwrap();
    std::fs::write(&key, "").unwrap();

    let held = hold_port();
    let target_https_port = held.local_addr().unwrap().port();
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 0
  admin_socket:
    path: "{sock}"
  admin_https:
    enabled: false
    host: "127.0.0.1"
    port: {https}
    cert_path: "{cert}"
    key_path: "{key}"
shutdown:
  drain_window_seconds: 2
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools: []
"#,
        https = target_https_port,
        sock = sock.display(),
        cert = cert.display(),
        key = key.display(),
        ops = ops.display(),
        db = db.display(),
    );
    let cfg = parse_config_str(&yaml).unwrap();
    // The configured port is held by this test, so a daemon that tried to
    // bind it would fail startup.
    let started = daemon::start_with_drain_window(cfg, Duration::from_secs(2))
        .await
        .expect("daemon starts without claiming the disabled admin HTTPS port");
    let (coord, handle) = (started.coord, started.handle);
    assert_eq!(
        started.addrs.admin_https, None,
        "admin HTTPS must not be bound when enabled=false"
    );
    drop(held);

    coord.trigger();
    timeout(Duration::from_secs(3), handle)
        .await
        .expect("daemon exits within 3s")
        .expect("join ok")
        .expect("daemon Ok(())");
}
