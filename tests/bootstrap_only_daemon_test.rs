//! T6.8 — the running daemon binds the bootstrap-only listener.
//!
//! `listen.bootstrap_only.enabled = true` must start a TLS listener that
//! accepts only `POST /admin/agent/register`, as
//! `docs/v2/runbooks/m6-mtls-onboarding.md` §7 promises. The router itself
//! is covered in-process by `bootstrap_only_listener_test.rs`; this file
//! covers the daemon wiring.

use agent_locksmith::admin::uds_client::UdsClient;
use agent_locksmith::config::parse_config_str;
use agent_locksmith::{argon2_helper, daemon, token};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

struct Fixture {
    dir: TempDir,
    ca_pem: String,
    op_token_wire: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let mut params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "bootstrap-listener-test");
        params.distinguished_name = dn;
        params
            .subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        std::fs::write(dir.path().join("bootstrap.crt"), cert.pem()).unwrap();
        std::fs::write(dir.path().join("bootstrap.key"), key.serialize_pem()).unwrap();

        let op = token::StructuredToken::generate(token::TokenNamespace::Operator);
        let hash =
            argon2_helper::hash(&secrecy::SecretString::from(op.secret.expose().to_string()))
                .unwrap();
        std::fs::write(
            dir.path().join("operators.yaml"),
            format!(
                "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{hash}\"\n",
                op.public_id.as_str()
            ),
        )
        .unwrap();
        Self {
            dir,
            ca_pem: cert.pem(),
            op_token_wire: op.wire_format(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// `admin_socket` is a YAML fragment (or empty); `bootstrap` is the
    /// body of the `bootstrap_only` block.
    fn yaml(&self, admin_socket: bool, bootstrap: &str) -> String {
        let socket = if admin_socket {
            format!(
                "  admin_socket:\n    path: \"{}\"\n",
                self.path("admin.sock").display()
            )
        } else {
            String::new()
        };
        format!(
            r#"
listen:
  host: "127.0.0.1"
  port: 0
{socket}  bootstrap_only:
{bootstrap}
    cert_path: "{cert}"
    key_path: "{key}"
shutdown:
  drain_window_seconds: 5
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools: []
"#,
            cert = self.path("bootstrap.crt").display(),
            key = self.path("bootstrap.key").display(),
            ops = self.path("operators.yaml").display(),
            db = self.path("locksmith.db").display(),
        )
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(self.ca_pem.as_bytes()).unwrap())
            .build()
            .unwrap()
    }

    async fn mint_bootstrap_token(&self) -> String {
        let bearer = format!("Bearer {}", self.op_token_wire);
        let (status, body) = UdsClient::new(self.path("admin.sock"))
            .request(
                "POST",
                "/admin/operator/bootstrap_tokens",
                &[
                    ("authorization", &bearer),
                    ("content-type", "application/json"),
                ],
                Some(br#"{"single_use": true}"#.to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(status, 200, "mint bootstrap token over UDS");
        let body: Value = serde_json::from_slice(&body).unwrap();
        body["token"].as_str().unwrap().to_string()
    }
}

const ENABLED: &str = "    enabled: true\n    host: \"127.0.0.1\"\n    port: 0";

async fn stop(started: daemon::StartedDaemon) {
    started.coord.trigger();
    tokio::time::timeout(Duration::from_secs(6), started.handle)
        .await
        .expect("daemon exits")
        .expect("join")
        .expect("clean shutdown");
}

#[tokio::test]
async fn enabled_listener_onboards_an_agent_that_can_then_call_the_agent_listener() {
    let f = Fixture::new();
    let cfg = parse_config_str(&f.yaml(true, ENABLED)).unwrap();
    let started = daemon::start_with_drain_window(cfg, Duration::from_secs(5))
        .await
        .expect("daemon starts");
    let port = started
        .addrs
        .bootstrap
        .expect("bootstrap-only listener bound")
        .port();
    let base = format!("https://127.0.0.1:{port}");
    let client = f.client();

    let refused = client
        .post(format!("{base}/admin/agent/register"))
        .json(&json!({"bootstrap_token": "lkbt_not.a-token", "name": "nobody"}))
        .send()
        .await
        .expect("bootstrap listener reachable");
    assert_eq!(
        refused.status(),
        401,
        "an invalid bootstrap token is refused"
    );

    let bootstrap_token = f.mint_bootstrap_token().await;
    let resp = client
        .post(format!("{base}/admin/agent/register"))
        .json(&json!({"bootstrap_token": bootstrap_token, "name": "agent-bs"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "register over the bootstrap listener");
    let body: Value = resp.json().await.unwrap();
    let agent_token = body["token"].as_str().unwrap().to_string();
    assert!(agent_token.starts_with("lk_"));

    let tools = reqwest::Client::new()
        .get(format!("http://{}/tools", started.addrs.agent))
        .bearer_auth(&agent_token)
        .send()
        .await
        .unwrap();
    assert_eq!(tools.status(), 200, "the enrolled agent authenticates");

    for path in ["/admin/operator/agents", "/admin/operator/bootstrap_tokens"] {
        let resp = client
            .get(format!("{base}{path}"))
            .bearer_auth(&f.op_token_wire)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "{path} is not served here");
    }
    stop(started).await;
}

#[tokio::test]
async fn disabled_block_binds_nothing() {
    let f = Fixture::new();
    let cfg = parse_config_str(&f.yaml(true, "    enabled: false")).unwrap();
    let started = daemon::start_with_drain_window(cfg, Duration::from_secs(5))
        .await
        .expect("daemon starts");
    assert_eq!(started.addrs.bootstrap, None);
    stop(started).await;
}

#[tokio::test]
async fn enabled_without_the_admin_substrate_refuses_to_start() {
    let f = Fixture::new();
    let cfg = parse_config_str(&f.yaml(false, ENABLED)).unwrap();
    let err = daemon::start_with_drain_window(cfg, Duration::from_secs(5))
        .await
        .err()
        .expect("daemon must not start without admin_socket");
    assert!(
        err.to_string().contains("bootstrap_only"),
        "error names the setting: {err}"
    );
}

#[tokio::test]
async fn a_port_already_in_use_refuses_to_start() {
    let f = Fixture::new();
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let block = format!("    enabled: true\n    host: \"127.0.0.1\"\n    port: {port}");
    let cfg = parse_config_str(&f.yaml(true, &block)).unwrap();
    let err = daemon::start_with_drain_window(cfg, Duration::from_secs(5))
        .await
        .err()
        .expect("daemon must not start when the bootstrap port is taken");
    assert!(
        err.to_string().contains("bootstrap-only listener"),
        "error names the listener: {err}"
    );
}
