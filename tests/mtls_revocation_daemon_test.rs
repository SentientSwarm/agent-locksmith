//! T6.3/T6.4 — the running daemon enforces mTLS revocation.
//!
//! `listen.mtls.blocklist_path` and `listen.mtls.crl_url` must reach the
//! agent listener's validator: a client cert whose serial is in the local
//! emergency blocklist (including one added by `locksmith mtls revoke`
//! while the daemon runs) or in the configured CRL is refused, as
//! `docs/v2/runbooks/m6-mtls-revocation.md` promises.

use agent_locksmith::config::parse_config_str;
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::{argon2_helper, daemon, migrations, token};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CrlIssuingDistributionPoint, DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use time::macros::datetime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const AGENT_SERIAL: u64 = 0x7a11;
const AGENT_SERIAL_HEX: &str = "7a11";

struct Pki {
    ca_pem: String,
    crl_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    agent_identity_pem: String,
}

fn mint_pki() -> Pki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "revocation-test-ca");
    ca_params.distinguished_name = dn;
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let server_key = KeyPair::generate().unwrap();
    let server = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

    let mut agent_params = CertificateParams::new(vec!["agent-r.local".to_string()]).unwrap();
    let mut agent_dn = DistinguishedName::new();
    agent_dn.push(DnType::CommonName, "agent-r");
    agent_params.distinguished_name = agent_dn;
    agent_params.serial_number = Some(SerialNumber::from(AGENT_SERIAL));
    let agent_key = KeyPair::generate().unwrap();
    let agent = agent_params.signed_by(&agent_key, &ca, &ca_key).unwrap();

    let crl = CertificateRevocationListParams {
        this_update: datetime!(2026-01-01 0:00 UTC),
        next_update: datetime!(2036-01-01 0:00 UTC),
        crl_number: SerialNumber::from(1u64),
        // Shaped like step-ca's: an IDP naming only a distribution point
        // with no port, which is not the URL locksmith fetches from.
        issuing_distribution_point: Some(CrlIssuingDistributionPoint {
            distribution_point: CrlDistributionPoint {
                uris: vec!["https://revocation-test.example/1.0/crl".into()],
            },
            scope: None,
        }),
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from(AGENT_SERIAL),
            revocation_time: datetime!(2026-01-01 0:00 UTC),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca, &ca_key)
    .unwrap();

    Pki {
        ca_pem: ca.pem(),
        crl_pem: crl.pem().unwrap(),
        server_cert_pem: server.pem(),
        server_key_pem: server_key.serialize_pem(),
        agent_identity_pem: format!("{}{}", agent.pem(), agent_key.serialize_pem()),
    }
}

struct Site {
    dir: TempDir,
    pki: Pki,
    blocklist: PathBuf,
}

impl Site {
    async fn new(blocklist_contents: Option<&str>) -> Self {
        let dir = TempDir::new().unwrap();
        let pki = mint_pki();
        for (name, body) in [
            ("ca.pem", &pki.ca_pem),
            ("server.crt", &pki.server_cert_pem),
            ("server.key", &pki.server_key_pem),
        ] {
            std::fs::write(dir.path().join(name), body).unwrap();
        }
        let blocklist = dir.path().join("blocklist.txt");
        if let Some(contents) = blocklist_contents {
            std::fs::write(&blocklist, contents).unwrap();
        }
        write_operators(&dir.path().join("operators.yaml"));
        let pool = migrations::open_and_migrate(&dir.path().join("locksmith.db"))
            .await
            .unwrap();
        let repo = AgentRepository::new(pool.clone());
        let (public_id, _) = repo
            .create("agent-r", None, None, None, None, None)
            .await
            .unwrap();
        repo.set_cert_identity(&public_id, Some("agent-r"))
            .await
            .unwrap();
        pool.close().await;
        Self {
            dir,
            pki,
            blocklist,
        }
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }

    fn yaml(&self, revocation: &str) -> String {
        format!(
            r#"
listen:
  host: "127.0.0.1"
  port: 0
  admin_socket:
    path: "{sock}"
  auth_mode: mtls
  mtls:
    ca_bundle_path: "{ca}"
    server_cert_path: "{cert}"
    server_key_path: "{key}"
{revocation}
shutdown:
  drain_window_seconds: 5
operator_credentials_path: "{ops}"
database:
  path: "{db}"
"#,
            sock = self.path("admin.sock"),
            ca = self.path("ca.pem"),
            cert = self.path("server.crt"),
            key = self.path("server.key"),
            ops = self.path("operators.yaml"),
            db = self.path("locksmith.db"),
        )
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(self.pki.ca_pem.as_bytes()).unwrap(),
            )
            .identity(reqwest::Identity::from_pem(self.pki.agent_identity_pem.as_bytes()).unwrap())
            .build()
            .unwrap()
    }
}

fn write_operators(p: &Path) {
    let op = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let hash =
        argon2_helper::hash(&secrecy::SecretString::from(op.secret.expose().to_string())).unwrap();
    std::fs::write(
        p,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{hash}\"\n",
            op.public_id.as_str()
        ),
    )
    .unwrap();
}

struct Running {
    coord: agent_locksmith::shutdown::ShutdownCoordinator,
    handle: tokio::task::JoinHandle<Result<(), daemon::DaemonError>>,
    port: u16,
}

impl Running {
    async fn start(yaml: &str) -> Self {
        let cfg = parse_config_str(yaml).expect("config parses");
        let started = daemon::start_with_drain_window(cfg, Duration::from_secs(5))
            .await
            .expect("daemon starts");
        Self {
            coord: started.coord,
            port: started.addrs.agent.port(),
            handle: started.handle,
        }
    }

    async fn tools_status(&self, client: &reqwest::Client) -> u16 {
        client
            .get(format!("https://127.0.0.1:{}/tools", self.port))
            .send()
            .await
            .expect("request reaches the agent listener")
            .status()
            .as_u16()
    }

    async fn stop(self) {
        self.coord.trigger();
        tokio::time::timeout(Duration::from_secs(6), self.handle)
            .await
            .expect("daemon exits")
            .expect("join")
            .expect("clean shutdown");
    }
}

#[tokio::test]
async fn blocklisted_serial_is_refused_from_startup() {
    let site = Site::new(Some(&format!("# test\n{AGENT_SERIAL_HEX}\n"))).await;
    let yaml = site.yaml(&format!(
        "    blocklist_path: \"{}\"",
        site.blocklist.display()
    ));
    let daemon = Running::start(&yaml).await;
    assert_eq!(daemon.tools_status(&site.client()).await, 401);
    daemon.stop().await;
}

#[tokio::test]
async fn serial_revoked_while_running_is_refused_after_reload() {
    let site = Site::new(Some("# no revocations yet\n")).await;
    let yaml = site.yaml(&format!(
        "    blocklist_path: \"{}\"\n    blocklist_reload_interval_seconds: 1",
        site.blocklist.display()
    ));
    let daemon = Running::start(&yaml).await;
    let client = site.client();
    assert_eq!(daemon.tools_status(&client).await, 200, "positive control");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_locksmith"))
        .args(["mtls", "revoke", AGENT_SERIAL_HEX, "--blocklist-path"])
        .arg(&site.blocklist)
        .args(["--reason", "revocation test"])
        .output()
        .unwrap();
    assert!(out.status.success(), "locksmith mtls revoke succeeds");

    // The same pooled connection must stop authenticating once the
    // daemon reloads the file.
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        let status = daemon.tools_status(&client).await;
        if status == 401 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "revoked serial still authenticated (status {status})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    daemon.stop().await;
}

#[tokio::test]
async fn crl_revoked_serial_is_refused() {
    let site = Site::new(None).await;
    let crl = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ca.crl"))
        .respond_with(ResponseTemplate::new(200).set_body_string(site.pki.crl_pem.clone()))
        .mount(&crl)
        .await;
    let yaml = site.yaml(&format!("    crl_url: \"{}/ca.crl\"", crl.uri()));
    let daemon = Running::start(&yaml).await;
    assert_eq!(daemon.tools_status(&site.client()).await, 401);
    daemon.stop().await;
}

#[tokio::test]
async fn crl_from_an_untrusted_signer_is_not_applied() {
    let site = Site::new(None).await;
    let impostor = mint_pki(); // same serial, different CA
    let crl = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ca.crl"))
        .respond_with(ResponseTemplate::new(200).set_body_string(impostor.crl_pem))
        .mount(&crl)
        .await;
    let yaml = site.yaml(&format!("    crl_url: \"{}/ca.crl\"", crl.uri()));
    let daemon = Running::start(&yaml).await;
    assert_eq!(
        daemon.tools_status(&site.client()).await,
        200,
        "an unsigned-by-our-CA CRL must not change revocation state"
    );
    daemon.stop().await;
}

#[tokio::test]
async fn last_good_crl_survives_a_restart_while_the_ca_is_down() {
    let site = Site::new(None).await;
    let crl = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ca.crl"))
        .respond_with(ResponseTemplate::new(200).set_body_string(site.pki.crl_pem.clone()))
        .up_to_n_times(1)
        .mount(&crl)
        .await;
    Mock::given(method("GET"))
        .and(path("/ca.crl"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&crl)
        .await;
    let yaml = site.yaml(&format!("    crl_url: \"{}/ca.crl\"", crl.uri()));
    let daemon = Running::start(&yaml).await;
    assert_eq!(daemon.tools_status(&site.client()).await, 401);
    daemon.stop().await;

    let restarted = Running::start(&yaml).await;
    assert_eq!(
        restarted.tools_status(&site.client()).await,
        401,
        "the cached CRL stays in force when the CA is unreachable"
    );
    restarted.stop().await;
}
