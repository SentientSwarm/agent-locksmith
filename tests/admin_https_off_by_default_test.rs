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

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn fixture_yaml(
    tcp: u16,
    sock: &std::path::Path,
    ops: &std::path::Path,
    db: &std::path::Path,
) -> String {
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {tcp}
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

    let target_https_port = pick_port();
    let tcp_port = pick_port();
    let cfg = parse_config_str(&fixture_yaml(tcp_port, &sock, &ops, &db)).unwrap();
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(2)).await;

    // Wait briefly so the daemon has its bind opportunity.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The target port must still be bindable — proves the daemon did
    // not claim it (since admin_https config is absent).
    let probe = std::net::TcpListener::bind(("127.0.0.1", target_https_port));
    assert!(
        probe.is_ok(),
        "admin HTTPS port should be bindable when block absent — daemon must not have claimed it"
    );
    drop(probe);

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

    let target_https_port = pick_port();
    let tcp_port = pick_port();
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {tcp}
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
        tcp = tcp_port,
        https = target_https_port,
        sock = sock.display(),
        cert = cert.display(),
        key = key.display(),
        ops = ops.display(),
        db = db.display(),
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(2)).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let probe = std::net::TcpListener::bind(("127.0.0.1", target_https_port));
    assert!(
        probe.is_ok(),
        "admin HTTPS port should be bindable when enabled=false — daemon must not have claimed it"
    );
    drop(probe);

    coord.trigger();
    timeout(Duration::from_secs(3), handle)
        .await
        .expect("daemon exits within 3s")
        .expect("join ok")
        .expect("daemon Ok(())");
}
