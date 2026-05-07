//! Post-v2 / #83 — admin HTTPS listener accepts client certs at the TLS
//! handshake under `admin_https.auth_mode: mtls` and resolves the cert
//! identity to an operator via `OperatorAuthenticator::authenticate_cert_identity`.
//!
//! T6.7 wire-side closure: M6 already shipped `OperatorRecord.cert_identity`
//! and the resolution path; this test pins that admin handlers actually
//! receive an authenticated `OperatorIdentity` derived from the peer cert
//! and that the resulting audit row records `auth_method=mtls` with
//! `operator_name` set.
//!
//! End-to-end shape:
//! 1. Mint CA + server cert + operator client cert with rcgen.
//! 2. operators.yaml binds `cert_identity = "alice@example.com"` to alice.
//! 3. Daemon config: `admin_https.auth_mode: mtls` + `admin_https.mtls.ca_bundle_path`.
//! 4. reqwest mTLS client POSTs `/admin/operator/agents` to create an agent.
//! 5. Audit query (direct repo) confirms `agent_create` row carries
//!    `auth_method=mtls` and `operator_name=alice`.

use agent_locksmith::config::parse_config_str;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository};
use agent_locksmith::{argon2_helper, daemon, migrations, token};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use serde_json::{Value, json};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct Pki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    operator_cert_pem: String,
    operator_key_pem: String,
}

fn mint_pki(server_host: &str, operator_cn: &str) -> Pki {
    // Self-signed CA (issues both server cert and operator client cert).
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-admin-mtls-ca");
    ca_params.distinguished_name = dn;
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Server cert (signed by CA) for the admin HTTPS listener.
    let mut server_params = CertificateParams::new(vec![server_host.to_string()]).unwrap();
    server_params
        .subject_alt_names
        .push(SanType::IpAddress(server_host.parse().unwrap()));
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    // Operator client cert (signed by CA). CN carries the operator's
    // cert_identity so MtlsValidator extracts it via the CN priority.
    let mut op_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut op_dn = DistinguishedName::new();
    op_dn.push(DnType::CommonName, operator_cn);
    op_params.distinguished_name = op_dn;
    let op_key = KeyPair::generate().unwrap();
    let op_cert = op_params.signed_by(&op_key, &ca_cert, &ca_key).unwrap();

    Pki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        operator_cert_pem: op_cert.pem(),
        operator_key_pem: op_key.serialize_pem(),
    }
}

fn write_operators_yaml(p: &std::path::Path, operator_cn: &str) -> String {
    let op_tok = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_tok.secret.expose().to_string(),
    ))
    .unwrap();
    std::fs::write(
        p,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n    cert_identity: \"{}\"\n",
            op_tok.public_id.as_str(),
            op_hash,
            operator_cn,
        ),
    )
    .unwrap();
    op_tok.public_id.as_str().to_string()
}

#[tokio::test]
async fn admin_https_mtls_authenticates_operator_via_client_cert() {
    let dir = TempDir::new().unwrap();
    let operator_cn = "alice@example.com";
    let pki = mint_pki("127.0.0.1", operator_cn);

    let ca_path = dir.path().join("ca.pem");
    let server_cert_path = dir.path().join("server.crt");
    let server_key_path = dir.path().join("server.key");
    std::fs::write(&ca_path, &pki.ca_pem).unwrap();
    std::fs::write(&server_cert_path, &pki.server_cert_pem).unwrap();
    std::fs::write(&server_key_path, &pki.server_key_pem).unwrap();

    let sock = dir.path().join("admin.sock");
    let ops_path = dir.path().join("operators.yaml");
    let db_path = dir.path().join("locksmith.db");
    let _op_public_id = write_operators_yaml(&ops_path, operator_cn);

    // Open the same DB for audit verification post-RPC.
    let pool = migrations::open_and_migrate(&db_path).await.unwrap();
    let audit = AuditRepository::new(pool);

    let agent_port = pick_port();
    let https_port = pick_port();
    let yaml = format!(
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
    cert_path: "{server_cert}"
    key_path: "{server_key}"
    auth_mode: mtls
    mtls:
      ca_bundle_path: "{ca}"
shutdown:
  drain_window_seconds: 5
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools: []
"#,
        agent_port = agent_port,
        https_port = https_port,
        sock = sock.display(),
        server_cert = server_cert_path.display(),
        server_key = server_key_path.display(),
        ca = ca_path.display(),
        ops = ops_path.display(),
        db = db_path.display(),
    );
    let cfg = parse_config_str(&yaml).expect("config parses with admin_https.auth_mode=mtls");
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;

    // Wait for the admin HTTPS listener to bind. With auth_mode=mtls the
    // listener requires client certs; we probe the TCP port until it's
    // open, then drive the real test request through reqwest.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::net::TcpStream::connect(("127.0.0.1", https_port)).is_err() {
        if std::time::Instant::now() > deadline {
            coord.trigger();
            let _ = timeout(Duration::from_secs(6), handle).await;
            panic!("admin HTTPS listener never bound on port {https_port}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Build a reqwest client with our CA + operator client cert.
    let ca = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap();
    let identity_pem = format!("{}{}", pki.operator_cert_pem, pki.operator_key_pem);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .identity(identity)
        .build()
        .unwrap();

    let base = format!("https://127.0.0.1:{https_port}");

    // POST /admin/operator/agents — no Authorization header; auth comes
    // from the client cert at the TLS handshake.
    let resp = client
        .post(format!("{base}/admin/operator/agents"))
        .json(&json!({"name": "agent-via-mtls"}))
        .send()
        .await
        .expect("admin HTTPS reachable from mTLS client");
    assert_eq!(
        resp.status(),
        200,
        "expected 200 from POST /admin/operator/agents with valid operator client cert"
    );
    let created: Value = resp.json().await.unwrap();
    let public_id = created["public_id"].as_str().unwrap().to_string();
    assert!(!created["token"].as_str().unwrap().is_empty());

    // Give the audit-write a beat to land (best-effort; INF-26 makes the
    // write fire-and-forget against the proxy hot path, but admin paths
    // are awaited).
    tokio::time::sleep(Duration::from_millis(150)).await;

    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let create_row = rows
        .iter()
        .find(|r| r.event == "agent_create" && r.agent_public_id.as_deref() == Some(&public_id))
        .expect("agent_create audit row exists for the mTLS-created agent");
    assert_eq!(
        create_row.auth_method.as_deref(),
        Some("mtls"),
        "audit row records auth_method=mtls; got: {:?}",
        create_row.auth_method
    );
    assert_eq!(
        create_row.operator_name.as_deref(),
        Some("alice"),
        "operator_name resolves to the cert-identity-bound operator; got: {:?}",
        create_row.operator_name
    );

    coord.trigger();
    timeout(Duration::from_secs(6), handle)
        .await
        .expect("daemon exits within 6s")
        .expect("join ok")
        .expect("daemon Ok(())");
}
