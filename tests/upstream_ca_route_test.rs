//! #135 — per-route upstream CA trust with partial-chain anchors.
//!
//! A real TLS upstream serves leaf + intermediate (root withheld, as with a
//! private cluster). Proves through the admin API and proxy router:
//!   - a route whose CA is the intermediate alone verifies (partial chain);
//!   - the same upstream without a route CA, or with an unrelated CA, fails;
//!   - unusable CA values and non-HTTPS upstreams are refused on write;
//!   - the admin read shows a fingerprint, never the PEM;
//!   - changing a route's CA clears its grants and bindings.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::app::build_app_full_with_phase_j;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{Catalog, RegistrationRepository};
use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository, BootstrapTokenRepository};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;

struct Chain {
    intermediate_pem: String,
    unrelated_ca_pem: String,
    port: u16,
}

fn ca(name: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    p.distinguished_name = dn;
    p
}

/// Root -> intermediate -> leaf (IP SAN 127.0.0.1). The server presents
/// leaf + intermediate; nobody is given the root.
async fn tls_upstream() -> Chain {
    agent_locksmith::admin::https::install_crypto_provider_once();
    let root_key = KeyPair::generate().unwrap();
    let root = ca("Test Root").self_signed(&root_key).unwrap();
    let int_key = KeyPair::generate().unwrap();
    let int = ca("Test Intermediate")
        .signed_by(&int_key, &root, &root_key)
        .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf_params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    let leaf = leaf_params.signed_by(&leaf_key, &int, &int_key).unwrap();
    let other_key = KeyPair::generate().unwrap();
    let other = ca("Unrelated CA").self_signed(&other_key).unwrap();

    let chain = format!("{}{}", leaf.pem(), int.pem());
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        chain.into_bytes(),
        leaf_key.serialize_pem().into_bytes(),
    )
    .await
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().route("/ping", axum::routing::get(|| async { "pong" }));
    tokio::spawn(axum_server::from_tcp_rustls(listener, tls).serve(app.into_make_service()));
    Chain {
        intermediate_pem: int.pem(),
        unrelated_ca_pem: other.pem(),
        port,
    }
}

struct H {
    _dir: TempDir,
    admin: TestServer,
    agent: TestServer,
    op: String,
    agent_bearer: String,
    pid: String,
}

async fn setup() -> H {
    let dir = TempDir::new().unwrap();
    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_token.secret.expose().to_string(),
    ))
    .unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{hash}\"\n",
            op_token.public_id.as_str()
        ),
    )
    .unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = agent_locksmith::repo::audit::AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let bindings = AgentCredentialRepository::new(pool.clone());
    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog = Arc::new(ArcSwap::from_pointee(catalog));
    let resolved = Arc::new(ArcSwap::from_pointee(Default::default()));
    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\ntools: []\n").unwrap();
    let cfg = Arc::new(ArcSwap::from_pointee(cfg));
    let (pid, secret) = agents
        .create("agent-1", None, None, None, None, None)
        .await
        .unwrap();
    let bearer =
        Arc::new(BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap());
    let bearer_dyn: Arc<dyn AgentAuthenticator> = bearer.clone();
    let uds = UdsState {
        admin: Arc::new(AdminService::new(
            agents,
            BootstrapTokenRepository::new(pool.clone()),
            cfg.clone(),
        )),
        agent_auth: bearer,
        operator_auth: Arc::new(OperatorAuthenticator::load(&ops_path).unwrap()),
        operator_mtls: None,
        registrations: Some(registrations.clone()),
        catalog: Some(catalog.clone()),
        resolved_creds: Some(resolved.clone()),
        oauth: None,
        agent_creds: Some(bindings.clone()),
        credential_sealing_key: None,
        credential_secrets: None,
        operational_log: None,
        operational_log_store: None,
        op_resolver: None,
    };
    let agent = build_app_full_with_phase_j(
        cfg,
        Some(audit),
        resolved,
        None,
        Some(bearer_dyn),
        Some(registrations),
        catalog,
        None,
        Some(bindings),
        None,
        None,
    );
    H {
        _dir: dir,
        admin: TestServer::new(build_router(uds)),
        agent: TestServer::new(agent),
        op: format!("Bearer {}", op_token.wire_format()),
        agent_bearer: format!("Bearer lk_{pid}.{}", secret.expose_secret()),
        pid,
    }
}

impl H {
    async fn put_route(&self, name: &str, body: Value) -> axum_test::TestResponse {
        self.admin
            .put(&format!("/admin/operator/models/{name}"))
            .add_header("authorization", &self.op)
            .json(&body)
            .await
    }

    /// Grant `names` and bind each to explicit no-auth.
    async fn grant(&self, names: &[&str]) {
        self.admin
            .patch(&format!("/admin/operator/agents/{}", self.pid))
            .add_header("authorization", &self.op)
            .json(&json!({ "allowlist": names }))
            .await
            .assert_status_no_content();
        for name in names {
            self.admin
                .put(&format!(
                    "/admin/operator/agents/{}/credentials/{name}",
                    self.pid
                ))
                .add_header("authorization", &self.op)
                .json(&json!({ "auth_spec": { "kind": "none" } }))
                .await
                .assert_status_ok();
        }
    }

    async fn ping(&self, name: &str) -> axum_test::TestResponse {
        self.agent
            .get(&format!("/api/{name}/ping"))
            .add_header("authorization", &self.agent_bearer)
            .await
    }
}

fn route(port: u16, ca: Option<&str>) -> Value {
    let mut body = json!({
        "upstream": format!("https://127.0.0.1:{port}"),
        "auth": { "kind": "none" },
        "egress": "direct",
    });
    if let Some(ca) = ca {
        body["upstream_ca_pem"] = json!(ca);
    }
    body
}

#[tokio::test]
async fn intermediate_anchor_verifies_only_its_own_route() {
    let chain = tls_upstream().await;
    let h = setup().await;
    h.put_route("private", route(chain.port, Some(&chain.intermediate_pem)))
        .await
        .assert_status_ok();
    h.put_route("public-roots", route(chain.port, None))
        .await
        .assert_status_ok();
    h.put_route("wrong-ca", route(chain.port, Some(&chain.unrelated_ca_pem)))
        .await
        .assert_status_ok();
    h.grant(&["private", "public-roots", "wrong-ca"]).await;

    let ok = h.ping("private").await;
    ok.assert_status_ok();
    assert_eq!(ok.text(), "pong");
    for untrusted in ["public-roots", "wrong-ca"] {
        let resp = h.ping(untrusted).await;
        assert_eq!(resp.status_code(), 502, "{untrusted}: {}", resp.text());
    }
}

#[tokio::test]
async fn admin_read_shows_fingerprint_not_pem() {
    let chain = tls_upstream().await;
    let h = setup().await;
    let put = h
        .put_route("private", route(chain.port, Some(&chain.intermediate_pem)))
        .await;
    put.assert_status_ok();
    let reg: Value = h
        .admin
        .get("/admin/operator/models/private")
        .add_header("authorization", &h.op)
        .await
        .json();
    assert_eq!(reg["upstream_ca"]["certificates"], 1);
    assert_eq!(reg["upstream_ca"]["sha256"].as_str().unwrap().len(), 64);
    assert!(!reg.to_string().contains("BEGIN CERTIFICATE"));
    assert!(!put.text().contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn unusable_ca_or_plain_http_is_refused() {
    let chain = tls_upstream().await;
    let h = setup().await;
    let junk = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let mut plain = route(chain.port, Some(&chain.intermediate_pem));
    plain["upstream"] = json!("http://127.0.0.1:1");
    for body in [
        route(chain.port, Some(junk)),
        route(chain.port, Some("")),
        plain,
    ] {
        let resp = h.put_route("bad", body).await;
        assert_eq!(resp.status_code(), 400);
        assert_eq!(resp.json::<Value>()["error"]["code"], "invalid_upstream_ca");
    }
}

#[tokio::test]
async fn changing_the_ca_clears_grants_and_bindings() {
    let chain = tls_upstream().await;
    let h = setup().await;
    h.put_route("private", route(chain.port, Some(&chain.intermediate_pem)))
        .await
        .assert_status_ok();
    h.grant(&["private"]).await;
    h.ping("private").await.assert_status_ok();

    // Same CA again: no change, authority kept.
    h.put_route("private", route(chain.port, Some(&chain.intermediate_pem)))
        .await
        .assert_status_ok();
    h.ping("private").await.assert_status_ok();

    // Different CA: grant and binding are gone.
    h.put_route("private", route(chain.port, Some(&chain.unrelated_ca_pem)))
        .await
        .assert_status_ok();
    assert_eq!(h.ping("private").await.status_code(), 403);
    let creds: Value = h
        .admin
        .get(&format!("/admin/operator/agents/{}/credentials", h.pid))
        .add_header("authorization", &h.op)
        .await
        .json();
    assert!(!creds.to_string().contains("\"private\""), "{creds}");
}
