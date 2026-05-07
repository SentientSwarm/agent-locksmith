//! T4.4 — CLI auto-detects --admin-url / LOCKSMITH_ADMIN_URL and routes
//! over HTTPS instead of UDS.
//!
//! Spawns `locksmithd` with both UDS and HTTPS bound, then runs the
//! CLI with --admin-url against the HTTPS endpoint and asserts:
//! - command succeeds (exit 0)
//! - JSON output is identical to a parallel run via UDS
//!
//! Identical output across transports is the M4 acceptance bullet.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use agent_locksmith::{argon2_helper, token};
use rcgen::{CertificateParams, KeyPair, SanType};
use serde_json::Value;
use tempfile::TempDir;

const LOCKSMITHD: &str = env!("CARGO_BIN_EXE_locksmithd");
const LOCKSMITH: &str = env!("CARGO_BIN_EXE_locksmith");

struct HttpsFixture {
    _dir: TempDir,
    socket_path: PathBuf,
    https_url: String,
    ca_bundle: PathBuf,
    op_token_wire: String,
    daemon: std::process::Child,
}

impl Drop for HttpsFixture {
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
            panic!("daemon did not bind {} within {timeout:?}", path.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn start_daemon_with_https() -> HttpsFixture {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("admin.sock");
    let ops_path = dir.path().join("operators.yaml");
    let db_path = dir.path().join("locksmith.db");
    let config_path = dir.path().join("config.yaml");
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");

    // Mint a self-signed cert with SAN IP=127.0.0.1.
    let mut params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

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

    let agent_port = pick_port();
    let https_port = pick_port();
    std::fs::write(
        &config_path,
        format!(
            r#"
listen:
  host: "127.0.0.1"
  port: {agent_port}
  admin_socket:
    path: "{sock}"
  admin_https:
    enabled: true
    host: "127.0.0.1"
    port: {https_port}
    cert_path: "{cert}"
    key_path: "{key}"
shutdown:
  drain_window_seconds: 5
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools: []
"#,
            sock = socket_path.display(),
            cert = cert_path.display(),
            key = key_path.display(),
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

    HttpsFixture {
        _dir: dir,
        socket_path,
        https_url: format!("https://127.0.0.1:{https_port}"),
        ca_bundle: cert_path,
        op_token_wire,
        daemon,
    }
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
fn cli_admin_url_flag_routes_over_https() {
    let f = start_daemon_with_https();

    // Create an agent over UDS so list-via-HTTPS has data to return.
    let mut create = Command::new(LOCKSMITH);
    create.arg("--socket").arg(&f.socket_path);
    create.args(["--format", "json"]);
    create.env("LOCKSMITH_OP_TOKEN", &f.op_token_wire).args([
        "agent",
        "register",
        "--name",
        "agent-cli-https",
    ]);
    let create_out = run(create);
    assert!(create_out.status.success(), "agent register over UDS works");

    // Now list agents via --admin-url HTTPS. The output must include the
    // agent we just created and match the UDS-served JSON byte-for-byte
    // (after parse normalization).
    let mut https_list = Command::new(LOCKSMITH);
    https_list.args(["--admin-url", &f.https_url]);
    https_list
        .arg("--ca-bundle")
        .arg(&f.ca_bundle)
        .args(["--format", "json"])
        .env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["agent", "list"]);
    let https_out = run(https_list);
    assert!(
        https_out.status.success(),
        "agent list over HTTPS exits 0; got: {}",
        String::from_utf8_lossy(&https_out.stderr),
    );
    let https_body: Value =
        serde_json::from_slice(&https_out.stdout).expect("CLI emits valid JSON over HTTPS");
    let names: Vec<&str> = https_body
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"agent-cli-https"),
        "list-over-HTTPS includes UDS-created agent"
    );

    // Compare against UDS-served list to assert identical responses.
    let mut uds_list = Command::new(LOCKSMITH);
    uds_list
        .arg("--socket")
        .arg(&f.socket_path)
        .args(["--format", "json"])
        .env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["agent", "list"]);
    let uds_out = run(uds_list);
    let uds_body: Value = serde_json::from_slice(&uds_out.stdout).unwrap();
    assert_eq!(
        https_body, uds_body,
        "UDS and HTTPS must return identical JSON for the same operation"
    );
}

#[test]
fn cli_admin_url_env_var_routes_over_https() {
    let f = start_daemon_with_https();

    // No --admin-url flag, but LOCKSMITH_ADMIN_URL set in env.
    let mut cmd = Command::new(LOCKSMITH);
    cmd.args(["--format", "json"])
        .env("LOCKSMITH_ADMIN_URL", &f.https_url)
        .env("LOCKSMITH_CA_BUNDLE", &f.ca_bundle)
        .env("LOCKSMITH_OP_TOKEN", &f.op_token_wire)
        .args(["agent", "list"]);
    let out = run(cmd);
    assert!(
        out.status.success(),
        "LOCKSMITH_ADMIN_URL routes CLI over HTTPS; got: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    // Should be a valid array (even if empty).
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(body.is_array(), "agent list returns JSON array");
}
