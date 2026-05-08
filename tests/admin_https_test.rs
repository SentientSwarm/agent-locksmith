//! T4.3 — Admin HTTPS listener serves the same handlers as the UDS path.
//!
//! Mints a CA + server cert at test time using rcgen, configures
//! `listen.admin_https` with cert/key paths, starts the daemon, and
//! exercises the admin surface from a reqwest client trusting the test
//! CA. Compares the HTTPS path against an equivalent UDS call to assert
//! the SPEC §4.2.5 contract: identical behavior between transports.
//!
//! Covers:
//! - T4.1 (deps wired)
//! - T4.2 (cert/key load)
//! - T4.3 (HTTPS listener bound + same router)
//! - T4.5 (bootstrap-token register works over HTTPS)

use agent_locksmith::admin::uds_client::UdsClient;
use agent_locksmith::config::parse_config_str;
use agent_locksmith::{argon2_helper, daemon, token};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct TestPki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
}

/// Mint a single-cert chain (self-signed CA used directly as server
/// cert) suitable for an integration test. Production deployments
/// would use a real CA + leaf; for our purposes the cert just needs to
/// (a) verify under a `add_root_certificate` configured client and
/// (b) be loadable by rustls.
fn mint_pki(host: &str) -> TestPki {
    let mut params = CertificateParams::new(vec![host.to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "agent-locksmith-test-ca");
    params.distinguished_name = dn;
    params
        .subject_alt_names
        .push(SanType::IpAddress(host.parse().unwrap()));

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    TestPki {
        ca_pem: cert.pem(),
        server_cert_pem: cert.pem(),
        server_key_pem: key_pair.serialize_pem(),
    }
}

struct Fixture {
    _dir: TempDir,
    socket_path: PathBuf,
    https_port: u16,
    tcp_port: u16,
    op_token_wire: String,
    pki: TestPki,
    cert_path: PathBuf,
    key_path: PathBuf,
    db_path: PathBuf,
    ops_path: PathBuf,
}

fn build_fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("admin.sock");
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");
    let db_path = dir.path().join("locksmith.db");
    let ops_path = dir.path().join("operators.yaml");

    let pki = mint_pki("127.0.0.1");
    std::fs::write(&cert_path, &pki.server_cert_pem).unwrap();
    std::fs::write(&key_path, &pki.server_key_pem).unwrap();

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

    Fixture {
        _dir: dir,
        socket_path,
        https_port: pick_port(),
        tcp_port: pick_port(),
        op_token_wire,
        pki,
        cert_path,
        key_path,
        db_path,
        ops_path,
    }
}

fn config_yaml(f: &Fixture) -> String {
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {tcp}
  admin_socket:
    path: "{sock}"
  admin_https:
    enabled: true
    host: "127.0.0.1"
    port: {https}
    cert_path: "{cert}"
    key_path: "{key}"
shutdown:
  drain_window_seconds: 5
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools: []
"#,
        tcp = f.tcp_port,
        https = f.https_port,
        sock = f.socket_path.display(),
        cert = f.cert_path.display(),
        key = f.key_path.display(),
        ops = f.ops_path.display(),
        db = f.db_path.display(),
    )
}

async fn wait_for_https(host: &str, port: u16, ca_pem: &str) -> reqwest::Client {
    let cert = reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()
        .unwrap();
    let url = format!("https://{host}:{port}/admin/operator/agents");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match client.get(&url).send().await {
            Ok(_resp) => return client,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("admin HTTPS never reachable: {e}"),
        }
    }
}

#[tokio::test]
async fn admin_https_create_and_list_agent_round_trip() {
    let f = build_fixture();
    let cfg = parse_config_str(&config_yaml(&f)).unwrap();
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;

    let client = wait_for_https("127.0.0.1", f.https_port, &f.pki.ca_pem).await;
    let base = format!("https://127.0.0.1:{}", f.https_port);
    let bearer = format!("Bearer {}", f.op_token_wire);

    // Create an agent over HTTPS.
    let resp = client
        .post(format!("{base}/admin/operator/agents"))
        .header("authorization", &bearer)
        .json(&json!({"name": "agent-https"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create over HTTPS");
    let created: Value = resp.json().await.unwrap();
    let public_id = created["public_id"].as_str().unwrap().to_string();
    assert!(!created["token"].as_str().unwrap().is_empty());

    // List over HTTPS — assert created agent appears.
    let listed: Value = client
        .get(format!("{base}/admin/operator/agents"))
        .header("authorization", &bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = listed["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"agent-https"), "agent visible over HTTPS");

    // Cross-transport contract: the same listing over UDS must include
    // the agent created via HTTPS (proves both transports hit the same
    // AdminService + database).
    let uds = UdsClient::new(&f.socket_path);
    let (_uds_status, uds_body_bytes) = uds
        .request(
            "GET",
            "/admin/operator/agents",
            &[("authorization", &bearer)],
            None,
        )
        .await
        .unwrap();
    let uds_body: Value = serde_json::from_slice(&uds_body_bytes).unwrap();
    let uds_names: Vec<&str> = uds_body["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert!(
        uds_names.contains(&"agent-https"),
        "HTTPS-created agent visible over UDS — single backing store"
    );

    // Audit must record the create operation; query over HTTPS.
    let audit: Value = client
        .get(format!("{base}/admin/operator/audit?event_class=operator"))
        .header("authorization", &bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let events: Vec<&str> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert!(
        events.contains(&"agent_create"),
        "audit row exists for HTTPS create; got: {events:?}"
    );

    // Audit row must reference the public_id we just created.
    let saw_id = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["agent_public_id"].as_str() == Some(public_id.as_str()));
    assert!(saw_id, "audit row carries created agent's public_id");

    coord.trigger();
    timeout(Duration::from_secs(6), handle)
        .await
        .expect("daemon exits within 6s")
        .expect("join ok")
        .expect("daemon Ok(())");
}

#[tokio::test]
async fn admin_https_bootstrap_register_works_without_bearer() {
    // T4.5 / D-10: bootstrap-token register stands on its own, regardless
    // of auth_mode. Over HTTPS, the same handler is reused, so the
    // register endpoint must accept a bootstrap-only request.
    let f = build_fixture();
    let cfg = parse_config_str(&config_yaml(&f)).unwrap();
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;
    let client = wait_for_https("127.0.0.1", f.https_port, &f.pki.ca_pem).await;
    let base = format!("https://127.0.0.1:{}", f.https_port);
    let op_bearer = format!("Bearer {}", f.op_token_wire);

    // Mint a bootstrap token via the operator surface.
    let mint: Value = client
        .post(format!("{base}/admin/operator/bootstrap_tokens"))
        .header("authorization", &op_bearer)
        .json(&json!({"single_use": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bootstrap_token = mint["token"].as_str().unwrap().to_string();
    assert!(bootstrap_token.starts_with("lkbt_"));

    // Register an agent using ONLY the bootstrap token — no operator
    // bearer; no other auth. Must succeed.
    let resp = client
        .post(format!("{base}/admin/agent/register"))
        .json(&json!({
            "bootstrap_token": bootstrap_token,
            "name": "agent-via-bootstrap",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "bootstrap register over HTTPS must work without bearer (D-10)"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(body["token"].as_str().unwrap().starts_with("lk_"));

    coord.trigger();
    timeout(Duration::from_secs(6), handle)
        .await
        .expect("daemon exits within 6s")
        .expect("join ok")
        .expect("daemon Ok(())");
}
