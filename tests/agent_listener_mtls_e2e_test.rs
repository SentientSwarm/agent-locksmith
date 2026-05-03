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
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository, Decision, EventClass};
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

/// Standard mTLS-deployment scaffolding shared across the agent-listener
/// mTLS e2e tests. Mints a CA + server cert + client cert via rcgen,
/// writes them to a fresh tempdir, opens a SQLite admin DB at a known
/// path, writes an operator credentials file, and returns the bag of
/// paths so the test can render the daemon YAML and pre-register
/// agents.
struct MtlsScaffold {
    dir: TempDir,
    pki: Pki,
    ca_path: std::path::PathBuf,
    server_cert_path: std::path::PathBuf,
    server_key_path: std::path::PathBuf,
    sock: std::path::PathBuf,
    ops_path: std::path::PathBuf,
    db_path: std::path::PathBuf,
    agent_port: u16,
}

impl MtlsScaffold {
    fn new(agent_cn: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let pki = mint_pki("127.0.0.1", agent_cn);
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
        Self {
            dir,
            pki,
            ca_path,
            server_cert_path,
            server_key_path,
            sock,
            ops_path,
            db_path,
            agent_port: pick_port(),
        }
    }

    /// Open the admin DB, return an `(AgentRepository, AuditRepository)`
    /// pair sharing one pool. The repos are dropped before the daemon
    /// opens its own pool, so test setup (agent registration,
    /// cert_identity binding) doesn't race the daemon's startup.
    async fn open_repos(&self) -> (AgentRepository, AuditRepository) {
        let pool = migrations::open_and_migrate(&self.db_path).await.unwrap();
        (AgentRepository::new(pool.clone()), AuditRepository::new(pool))
    }
}

impl Drop for MtlsScaffold {
    fn drop(&mut self) {
        // Tidy server key permissions so the TempDir destructor doesn't
        // hit a permission-denied path on some platforms.
        std::fs::set_permissions(
            &self.server_key_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .ok();
        // dir is dropped after this; explicit so a future reader sees it.
        let _ = &self.dir;
    }
}

/// Spawn the daemon with the given YAML, wait for the agent listener
/// to bind, and return the shutdown coordinator + join handle. The
/// caller is responsible for `coord.trigger()` + `timeout(handle)` at
/// the end of the test.
async fn spawn_mtls_daemon(
    yaml: &str,
    agent_port: u16,
) -> (
    agent_locksmith::shutdown::ShutdownCoordinator,
    tokio::task::JoinHandle<Result<(), agent_locksmith::daemon::DaemonError>>,
) {
    let cfg = parse_config_str(yaml).expect("config parses");
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::net::TcpStream::connect(("127.0.0.1", agent_port)).is_err() {
        if std::time::Instant::now() > deadline {
            panic!("agent listener never bound on port {agent_port}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (coord, handle)
}

/// Build a reqwest client that trusts the test CA and presents the
/// agent's client cert.
fn mtls_reqwest_client(pki: &Pki) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).unwrap();
    let identity_pem = format!("{}{}", pki.agent_cert_pem, pki.agent_key_pem);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(ca)
        .identity(identity)
        .build()
        .unwrap()
}

#[tokio::test]
async fn agent_listener_mtls_authenticates_via_client_cert() {
    let scaffold = MtlsScaffold::new("agent-7");
    let (repo, audit) = scaffold.open_repos().await;

    // Pre-register the agent + bind cert_identity. The mTLS bind path
    // doesn't have a registration flow; agents are pre-registered.
    let (public_id, _secret) = repo
        .create("agent-7", None, None, None, None, None)
        .await
        .unwrap();
    repo.set_cert_identity(&public_id, Some("agent-7"))
        .await
        .unwrap();
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
        agent_port = scaffold.agent_port,
        sock = scaffold.sock.display(),
        ca = scaffold.ca_path.display(),
        server_cert = scaffold.server_cert_path.display(),
        server_key = scaffold.server_key_path.display(),
        ops = scaffold.ops_path.display(),
        db = scaffold.db_path.display(),
        upstream = mock.uri(),
    );
    let (coord, handle) = spawn_mtls_daemon(&yaml, scaffold.agent_port).await;
    let client = mtls_reqwest_client(&scaffold.pki);

    let url = format!(
        "https://127.0.0.1:{}/api/ping/v1/ping",
        scaffold.agent_port
    );
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

    unsafe { std::env::remove_var("AGENT_LISTENER_MTLS_TEST_KEY") };
}

// TS-14 (M9): mTLS-derived AgentIdentity flows through the same ACL gate
// as bearer-derived identity. This is the cross-coverage e2e the SPEC's
// §6.2 #M9 testing table promises — the unit test on `check_tool_acl`
// verifies the function is auth-method-agnostic, but only this test
// proves the mTLS code path actually surfaces the identity to the
// `proxy_handler` ACL gate.
#[tokio::test]
async fn ts14_mtls_identity_acl_gate_denies_in_denylist() {
    let scaffold = MtlsScaffold::new("agent-mtls-deny");
    let (repo, audit) = scaffold.open_repos().await;

    // Pre-register the agent with a denylist that includes the tool we
    // will request. The mTLS handshake will resolve the agent identity
    // (via cert_identity binding) and the proxy ACL gate must then 403.
    let (public_id, _secret) = repo
        .create(
            "agent-mtls-deny",
            None,
            None,
            Some(&["ping".to_string()]), // denylist
            None,
            None,
        )
        .await
        .unwrap();
    repo.set_cert_identity(&public_id, Some("agent-mtls-deny"))
        .await
        .unwrap();
    drop(repo);

    // Mock upstream (must NEVER be hit — the ACL gate stops the request
    // before tool resolution).
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_string("should-not-reach"))
        .mount(&mock)
        .await;

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
"#,
        agent_port = scaffold.agent_port,
        sock = scaffold.sock.display(),
        ca = scaffold.ca_path.display(),
        server_cert = scaffold.server_cert_path.display(),
        server_key = scaffold.server_key_path.display(),
        ops = scaffold.ops_path.display(),
        db = scaffold.db_path.display(),
        upstream = mock.uri(),
    );
    let (coord, handle) = spawn_mtls_daemon(&yaml, scaffold.agent_port).await;
    let client = mtls_reqwest_client(&scaffold.pki);

    let url = format!(
        "https://127.0.0.1:{}/api/ping/v1/ping",
        scaffold.agent_port
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("request reaches daemon");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "denylist match must produce 403; got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("error body parses");
    assert_eq!(body["error"]["type"], "authz_error");
    assert_eq!(body["error"]["code"], "tool_not_allowed");

    // Confirm the upstream was never reached — the ACL gate runs before
    // tool resolution / outbound dispatch.
    let upstream_received = mock.received_requests().await.unwrap_or_default();
    assert!(
        upstream_received.is_empty(),
        "ACL deny must short-circuit before any upstream call; got {} hits",
        upstream_received.len()
    );

    // Audit row records the deny with mtls auth_method and the cert-bound
    // agent_public_id. Tighten to exactly-1 (vs find()) so a future
    // double-write regression is caught.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let deny_rows: Vec<_> = rows
        .iter()
        .filter(|r| r.event_class == EventClass::Security && r.event == "authz_denied")
        .collect();
    assert_eq!(deny_rows.len(), 1, "exactly one authz_denied row");
    let deny_row = deny_rows[0];
    assert_eq!(deny_row.decision, Decision::Denied);
    assert_eq!(deny_row.status, Some(403));
    assert_eq!(deny_row.tool.as_deref(), Some("ping"));
    assert_eq!(
        deny_row.auth_method.as_deref(),
        Some("mtls"),
        "M9 ACL gate records the mTLS auth_method"
    );
    assert_eq!(
        deny_row.agent_public_id.as_deref(),
        Some(public_id.as_str()),
        "agent_public_id matches the cert-identity-bound agent"
    );
    assert_eq!(
        deny_row
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str()),
        Some("in_denylist"),
        "deny reason recorded"
    );

    coord.trigger();
    timeout(Duration::from_secs(6), handle)
        .await
        .expect("daemon exits within 6s")
        .expect("join ok")
        .expect("daemon Ok(())");
}
