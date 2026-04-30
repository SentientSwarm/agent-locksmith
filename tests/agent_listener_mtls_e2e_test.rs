//! Post-v2 / #67 — agent listener accepts client certs at the TLS
//! handshake under `auth_mode: mtls` and binds the cert identity to
//! an agent record.
//!
//! End-to-end shape:
//! 1. Mint CA + server cert + agent cert with rcgen.
//! 2. Configure daemon with auth_mode=mtls + mtls.{ca_bundle_path,
//!    server_cert_path, server_key_path}.
//! 3. Register an agent and bind cert_identity = "agent-7" via the
//!    repo helper.
//! 4. Make an HTTPS request from a reqwest client carrying the agent
//!    client cert; assert the upstream sees the agent's resolved
//!    credential and the audit row records `auth_method=mtls`.

use agent_locksmith::config::parse_config_str;
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository};
use agent_locksmith::{argon2_helper, daemon, migrations, token};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
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

struct Pki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    agent_cert_pem: String,
    agent_key_pem: String,
}

fn mint_pki(server_host: &str, agent_cn: &str) -> Pki {
    // Self-signed CA (issues both server cert and agent client cert).
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-mtls-ca");
    ca_params.distinguished_name = dn;
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Server cert (signed by CA).
    let mut server_params = CertificateParams::new(vec![server_host.to_string()]).unwrap();
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(server_host.parse().unwrap()));
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    // Agent client cert (signed by CA).
    let mut agent_params = CertificateParams::new(vec![format!("{agent_cn}.local")]).unwrap();
    let mut agent_dn = DistinguishedName::new();
    agent_dn.push(DnType::CommonName, agent_cn);
    agent_params.distinguished_name = agent_dn;
    let agent_key = KeyPair::generate().unwrap();
    let agent_cert = agent_params
        .signed_by(&agent_key, &ca_cert, &ca_key)
        .unwrap();

    Pki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        agent_cert_pem: agent_cert.pem(),
        agent_key_pem: agent_key.serialize_pem(),
    }
}

fn write_operators_yaml(p: &std::path::Path) {
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
}

#[tokio::test]
async fn agent_listener_mtls_authenticates_via_client_cert() {
    let dir = TempDir::new().unwrap();
    let pki = mint_pki("127.0.0.1", "agent-7");

    let ca_path = dir.path().join("ca.pem");
    let server_cert_path = dir.path().join("server.crt");
    let server_key_path = dir.path().join("server.key");
    std::fs::write(&ca_path, &pki.ca_pem).unwrap();
    std::fs::write(&server_cert_path, &pki.server_cert_pem).unwrap();
    std::fs::write(&server_key_path, &pki.server_key_pem).unwrap();

    let sock = dir.path().join("admin.sock");
    let ops_path = dir.path().join("operators.yaml");
    let db_path = dir.path().join("locksmith.db");
    write_operators_yaml(&ops_path);

    // Pre-register the agent + bind cert_identity. The mTLS bind path
    // doesn't have a registration flow; agents are pre-registered.
    let pool = migrations::open_and_migrate(&db_path).await.unwrap();
    let repo = AgentRepository::new(pool.clone());
    let (public_id, _secret) = repo
        .create("agent-7", None, None, None, None, None)
        .await
        .unwrap();
    repo.set_cert_identity(&public_id, Some("agent-7"))
        .await
        .unwrap();
    let audit = AuditRepository::new(pool);
    drop(repo);

    // Mock upstream that asserts the credential header (proves the
    // proxy injected the agent's resolved credential after mTLS
    // authentication).
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer fixed-test-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let agent_port = pick_port();
    // SAFETY: tests intentionally manipulate env; var name unique.
    unsafe { std::env::set_var("AGENT_LISTENER_MTLS_TEST_KEY", "fixed-test-secret") };
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {agent_port}
  admin_socket:
    path: "{sock}"
  auth_mode: mtls
  mtls:
    ca_bundle_path: "{ca}"
    server_cert_path: "{server_cert}"
    server_key_path: "{server_key}"
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
        from_env:
          var: AGENT_LISTENER_MTLS_TEST_KEY
          prefix: "Bearer "
"#,
        sock = sock.display(),
        ca = ca_path.display(),
        server_cert = server_cert_path.display(),
        server_key = server_key_path.display(),
        ops = ops_path.display(),
        db = db_path.display(),
        upstream = mock.uri(),
    );
    let cfg = parse_config_str(&yaml).expect("config parses");
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;

    // Wait for the agent listener to bind. With auth_mode=mtls the
    // listener is a TLS endpoint; we probe by attempting a TLS
    // connection (no client cert yet — should fail handshake but
    // confirm the port is open).
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::net::TcpStream::connect(("127.0.0.1", agent_port)).is_err() {
        if std::time::Instant::now() > deadline {
            panic!("agent listener never bound on port {agent_port}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Build a reqwest client with our CA + agent client cert.
    let ca = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap();
    let identity_pem = format!("{}{}", pki.agent_cert_pem, pki.agent_key_pem);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .identity(identity)
        .build()
        .unwrap();

    let url = format!("https://127.0.0.1:{agent_port}/api/ping/v1/ping");
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("request reaches daemon");
    assert!(
        resp.status().is_success(),
        "expected 200, got {}",
        resp.status()
    );

    // Audit row records auth_method=mtls.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let proxy_row = rows
        .iter()
        .find(|r| r.event == "proxy_request")
        .expect("proxy_request audit row exists");
    assert_eq!(
        proxy_row.auth_method.as_deref(),
        Some("mtls"),
        "auth_method records mtls; got: {:?}",
        proxy_row.auth_method
    );
    assert_eq!(
        proxy_row.agent_public_id.as_deref(),
        Some(public_id.as_str()),
        "agent_public_id matches the cert-identity-bound agent"
    );

    coord.trigger();
    timeout(Duration::from_secs(6), handle)
        .await
        .expect("daemon exits within 6s")
        .expect("join ok")
        .expect("daemon Ok(())");

    // Permission tidy.
    std::fs::set_permissions(&server_key_path, std::fs::Permissions::from_mode(0o600)).ok();
    unsafe { std::env::remove_var("AGENT_LISTENER_MTLS_TEST_KEY") };
}
