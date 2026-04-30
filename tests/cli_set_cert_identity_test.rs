//! Post-v2 / #79 — `locksmith agent set-cert-identity` CLI wrapper.
//!
//! The M6 onboarding runbook §4 currently tells operators to bind an
//! agent's mTLS cert identity by editing the SQLite column directly.
//! `AgentRepository::set_cert_identity` already exists; this test pins
//! the CLI surface that goes through it: subprocess CLI register →
//! set-cert-identity → get (asserts the value is set) → set-cert-identity
//! --clear → get (asserts the value is None).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agent_locksmith::{argon2_helper, token};
use serde_json::Value;
use tempfile::TempDir;

const LOCKSMITHD: &str = env!("CARGO_BIN_EXE_locksmithd");
const LOCKSMITH: &str = env!("CARGO_BIN_EXE_locksmith");

struct Fixture {
    _dir: TempDir,
    socket_path: PathBuf,
    op_token_wire: String,
    daemon: std::process::Child,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn wait_for_socket(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() > deadline {
            panic!(
                "daemon did not bind {} within {:?}",
                path.display(),
                timeout
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn start_daemon() -> Fixture {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("admin.sock");
    let ops_path = dir.path().join("operators.yaml");
    let db_path = dir.path().join("locksmith.db");
    let config_path = dir.path().join("config.yaml");
    let port = pick_port();

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

    std::fs::write(
        &config_path,
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
            sock = socket_path.display(),
            ops = ops_path.display(),
            db = db_path.display(),
        ),
    )
    .unwrap();

    let daemon = Command::new(LOCKSMITHD)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("locksmithd spawns");

    wait_for_socket(&socket_path, Duration::from_secs(5));

    Fixture {
        _dir: dir,
        socket_path,
        op_token_wire,
        daemon,
    }
}

fn cli(socket: &Path) -> Command {
    let mut c = Command::new(LOCKSMITH);
    c.arg("--socket").arg(socket).arg("--format").arg("json");
    c
}

fn run_ok(mut cmd: Command) -> std::process::Output {
    let out = cmd.output().expect("CLI runs");
    if !out.status.success() {
        eprintln!(
            "CLI exited {}: stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    assert!(out.status.success(), "CLI exits 0");
    out
}

#[test]
fn agent_set_cert_identity_round_trip() {
    let f = start_daemon();

    // Register agent.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["agent", "register", "--name", "agent-79"]);
    let out = run_ok(cmd);
    let body: Value = serde_json::from_slice(&out.stdout).expect("json output");
    let public_id = body["public_id"].as_str().unwrap().to_string();

    // Set the cert_identity. Wraps AgentRepository::set_cert_identity
    // through the operator-authed admin endpoint.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
        "agent",
        "set-cert-identity",
        &public_id,
        "agent-79@example.com",
    ]);
    run_ok(cmd);

    // Verify via `agent get` — the response surfaces cert_identity so
    // operators can inspect bindings without dropping into SQL.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["agent", "get", &public_id]);
    let out = run_ok(cmd);
    let got: Value = serde_json::from_slice(&out.stdout).expect("json output");
    assert_eq!(
        got["cert_identity"].as_str(),
        Some("agent-79@example.com"),
        "cert_identity set via CLI surfaces in `agent get`; got: {:?}",
        got["cert_identity"]
    );

    // Clear the cert_identity using `--clear`.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
        "agent",
        "set-cert-identity",
        &public_id,
        "--clear",
    ]);
    run_ok(cmd);

    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["agent", "get", &public_id]);
    let out = run_ok(cmd);
    let got: Value = serde_json::from_slice(&out.stdout).expect("json output");
    assert!(
        got["cert_identity"].is_null(),
        "cert_identity cleared via CLI --clear; got: {:?}",
        got["cert_identity"]
    );
}
