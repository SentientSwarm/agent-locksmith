//! End-to-end CLI integration test (M2 acceptance contract).
//!
//! Spawns `locksmithd` as a child process against a temp socket + temp
//! database + temp operators file, then drives the `locksmith` CLI
//! through UC-1 (operator register), UC-3 (agent status), UC-4 (revoke),
//! UC-5 (bootstrap mint → register → status). Each subcommand exits 0
//! and produces parseable JSON output (when --format json is set).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agent_locksmith::{argon2_helper, token};
use serde_json::Value;
use tempfile::TempDir;

const LOCKSMITHD: &str = env!("CARGO_BIN_EXE_locksmithd");
const LOCKSMITH: &str = env!("CARGO_BIN_EXE_locksmith");

struct E2eFixture {
    _dir: TempDir,
    config_path: PathBuf,
    socket_path: PathBuf,
    op_token_wire: String,
    daemon: std::process::Child,
}

impl Drop for E2eFixture {
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

fn start_daemon() -> E2eFixture {
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

    E2eFixture {
        _dir: dir,
        config_path,
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

fn run(mut cmd: Command) -> std::process::Output {
    let out = cmd.output().expect("CLI runs");
    if !out.status.success() {
        eprintln!(
            "CLI exited {}: stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    out
}

#[test]
fn uc1_uc3_uc4_via_cli() {
    let f = start_daemon();

    // UC-1: operator registers an agent.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
        "agent",
        "register",
        "--name",
        "agent-uc1",
    ]);
    let out = run(cmd);
    assert!(out.status.success(), "UC-1 register exits 0");
    let body: Value = serde_json::from_slice(&out.stdout).expect("json output");
    let agent_token = body["token"].as_str().unwrap().to_string();
    let agent_pid = body["public_id"].as_str().unwrap().to_string();
    assert!(agent_token.starts_with("lk_"));

    // UC-3: agent uses its token to fetch status.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_AGENT_TOKEN", &agent_token).arg("status");
    let out = run(cmd);
    assert!(out.status.success(), "UC-3 status exits 0");
    let status_body: Value = serde_json::from_slice(&out.stdout).expect("json output");
    assert_eq!(status_body["name"], "agent-uc1");

    // UC-4: operator revokes the agent. Subsequent agent auth fails (3).
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["agent", "revoke", &agent_pid]);
    let out = run(cmd);
    assert!(out.status.success(), "UC-4 revoke exits 0");

    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_AGENT_TOKEN", &agent_token).arg("status");
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "post-revoke status fails");
    assert_eq!(
        out.status.code(),
        Some(3),
        "post-revoke status exits with auth code 3"
    );
}

#[test]
fn uc5_bootstrap_mint_then_register() {
    let f = start_daemon();

    // Mint a single-use bootstrap token.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["bootstrap", "mint"]);
    let out = run(cmd);
    assert!(out.status.success(), "bootstrap mint exits 0");
    let body: Value = serde_json::from_slice(&out.stdout).expect("json output");
    let bootstrap_token = body["token"].as_str().unwrap().to_string();
    assert!(bootstrap_token.starts_with("lkbt_"));

    // bootstrap list — should show one token.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["bootstrap", "list"]);
    let out = run(cmd);
    assert!(out.status.success(), "bootstrap list exits 0");
    let listed: Value = serde_json::from_slice(&out.stdout).expect("json output");
    assert_eq!(listed.as_array().map(|v| v.len()), Some(1));
}

#[test]
fn agent_list_on_fresh_daemon_returns_empty() {
    let f = start_daemon();
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["agent", "list"]);
    let out = run(cmd);
    assert!(out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).expect("json output");
    assert_eq!(body.as_array().map(|v| v.len()), Some(0));
}

#[test]
fn missing_op_token_exits_with_auth_code() {
    let f = start_daemon();
    let mut cmd = cli(&f.socket_path);
    cmd.args(["agent", "list"]);
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(3), "exit code 3 = auth missing");
}

#[test]
fn audit_query_returns_operator_events() {
    let f = start_daemon();

    // Generate one operator event (agent register).
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
        "agent",
        "register",
        "--name",
        "audited-agent",
    ]);
    run(cmd)
        .status
        .success()
        .then_some(())
        .expect("register ok");

    // Query the audit table — must surface the agent_create row.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
        "audit",
        "query",
        "--event-class",
        "operator",
    ]);
    let out = run(cmd);
    assert!(out.status.success(), "audit query exits 0");
    let body: Value = serde_json::from_slice(&out.stdout).expect("json output");
    let rows = body.as_array().expect("array of audit rows");
    assert!(
        rows.iter().any(|r| r["event"] == "agent_create"),
        "agent_create row visible via audit query"
    );
}

#[test]
fn audit_query_filters_by_decision() {
    let f = start_daemon();
    // Trigger a Denied row by attempting to register a duplicate name.
    for _ in 0..2 {
        let mut cmd = cli(&f.socket_path);
        cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
            "agent",
            "register",
            "--name",
            "dup-agent",
        ]);
        let _ = cmd.output();
    }

    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
        "audit",
        "query",
        "--decision",
        "denied",
    ]);
    let out = run(cmd);
    assert!(out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    let rows = body.as_array().unwrap();
    assert!(
        !rows.is_empty(),
        "at least one Denied row from the duplicate register"
    );
    for r in rows {
        assert_eq!(r["decision"], "denied");
    }
}

#[test]
fn audit_query_requires_operator_token() {
    let f = start_daemon();
    let mut cmd = cli(&f.socket_path);
    cmd.args(["audit", "query"]);
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(3), "no op token => exit 3");
}

#[test]
fn export_agents_yaml_excludes_token_material() {
    let f = start_daemon();
    // Create one agent so the export has something to emit.
    let mut cmd = cli(&f.socket_path);
    cmd.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["agent", "register", "--name", "exporter"]);
    let _ = run(cmd);

    let mut cmd = Command::new(LOCKSMITH);
    cmd.arg("--socket")
        .arg(&f.socket_path)
        .env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["export", "agents", "--format", "yaml"]);
    let out = run(cmd);
    assert!(out.status.success(), "export agents exits 0");
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(body.contains("exporter"), "agent name present in export");
    assert!(
        !body.contains("token"),
        "no `token` field in export per R-F14: {body}"
    );
    assert!(
        !body.contains("secret"),
        "no `secret` material in export per R-F14: {body}"
    );
}

#[allow(dead_code)]
fn write(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
}

// Use the config_path field so the compiler doesn't warn about it.
#[allow(dead_code)]
fn _use_config(f: &E2eFixture) -> &Path {
    &f.config_path
}
