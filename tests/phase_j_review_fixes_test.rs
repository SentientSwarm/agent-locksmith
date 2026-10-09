//! Phase J review fixes (issue #94) — regression suite for the PR #93
//! REQUEST_CHANGES findings.
//!
//! One substrate wires the SAME `op` resolver into the admin router and
//! the proxy (as the daemon does), so admin writes resync the cache:
//!   - an `op_*` registration added at runtime resolves without a restart;
//!   - an `op` reference used only by a per-agent override resolves;
//!   - clearing a stored per-agent override tombstones its sealed value;
//!   - a stored credential on a seed row makes the row operator-owned;
//!   - stored credentials keep a header-auth registration header-shaped;
//!   - a sealed value orphaned by a generic override replacement is
//!     collected by the credential-store GC.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::app::build_app_full_with_phase_k;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::audit::AuditRepository;
use agent_locksmith::repo::{
    AgentCredentialRepository, AgentRepository, BootstrapTokenRepository,
    CredentialSecretsRepository,
};
use agent_locksmith::secret::{OpCommand, OpResolver, resync_op_references};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LATE_REF: &str = "op://vault/item/late";
const OVERRIDE_REF: &str = "op://vault/item/override";
const HDR_REF: &str = "op://vault/item/hdr";

struct CountingFakeOp {
    values: HashMap<String, String>,
    calls: Arc<AtomicU64>,
}

impl OpCommand for CountingFakeOp {
    fn read(&self, reference: &str) -> Result<SecretString, String> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.values
            .get(reference)
            .map(|v| SecretString::from(v.clone()))
            .ok_or_else(|| "item not found".to_string())
    }
}

struct Harness {
    _dir: TempDir,
    admin: TestServer,
    agent: TestServer,
    op_bearer: String,
    agent_bearer: String,
    agent_public_id: String,
    agent_id: i64,
    op_calls: Arc<AtomicU64>,
    registrations: Arc<RegistrationRepository>,
    agent_creds: AgentCredentialRepository,
    secrets: CredentialSecretsRepository,
    mock: MockServer,
}

fn model(name: &str, upstream: &str, auth: AuthSpec) -> Registration {
    Registration::new(
        name.to_string(),
        Kind::Model,
        String::new(),
        upstream.to_string(),
        auth,
    )
}

async fn setup() -> Harness {
    let dir = TempDir::new().unwrap();

    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_bearer = format!("Bearer {}", op_token.wire_format());
    let token_hash =
        argon2_helper::hash(&SecretString::from(op_token.secret.expose().to_string())).unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_token.public_id.as_str(),
            token_hash
        ),
    )
    .unwrap();

    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let secrets = CredentialSecretsRepository::new(pool.clone());
    let agent_creds = AgentCredentialRepository::new(pool.clone());
    let key = agent_locksmith::secret::CredentialSealingKey::generate().unwrap();
    let mock = MockServer::start().await;

    let mut seed_row = model(
        "seed-api",
        &mock.uri(),
        AuthSpec::Bearer {
            env_var: "SEED_KEY".into(),
        },
    );
    seed_row.seed = true;
    for r in [
        model("shared-api", &mock.uri(), AuthSpec::None),
        model(
            "hdr-api",
            &mock.uri(),
            AuthSpec::Header {
                header: "x-api-key".into(),
                env_var: "HDR_KEY".into(),
            },
        ),
        model(
            "ophdr-api",
            &mock.uri(),
            AuthSpec::OpHeader {
                header: "x-api-key".into(),
                reference: HDR_REF.into(),
            },
        ),
        seed_row,
    ] {
        registrations.create(&r).await.unwrap();
    }

    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));
    let resolved_arc = Arc::new(ArcSwap::from_pointee(Default::default()));
    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\ntools: []\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    let acl: Vec<String> = ["shared-api", "hdr-api", "ophdr-api", "seed-api", "late-api"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (pid, secret) = agents
        .create("agent-1", None, Some(&acl), None, None, None)
        .await
        .unwrap();
    let agent_bearer = format!("Bearer lk_{pid}.{}", secret.expose_secret());
    let record = agents.get_by_name("agent-1").await.unwrap().unwrap();

    let bearer_concrete =
        Arc::new(BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap());
    let bearer_dyn: Arc<dyn AgentAuthenticator> = bearer_concrete.clone();
    let operator_auth = Arc::new(OperatorAuthenticator::load(&ops_path).unwrap());
    let admin_service = Arc::new(AdminService::with_audit_and_creds(
        agents,
        bootstrap,
        cfg_arc.clone(),
        Some(audit.clone()),
        resolved_arc.clone(),
    ));

    let op_calls = Arc::new(AtomicU64::new(0));
    let op_resolver = Arc::new(OpResolver::new(
        Box::new(CountingFakeOp {
            values: HashMap::from([
                (LATE_REF.to_string(), "late-value".to_string()),
                (OVERRIDE_REF.to_string(), "override-op-value".to_string()),
                (HDR_REF.to_string(), "hdr-op-value".to_string()),
            ]),
            calls: op_calls.clone(),
        }),
        None,
    ));
    // Startup sync, as the daemon does.
    resync_op_references(&op_resolver, &catalog_arc.load(), Some(&agent_creds)).await;

    let uds = UdsState {
        admin: admin_service,
        agent_auth: bearer_concrete,
        operator_auth,
        operator_mtls: None,
        registrations: Some(registrations.clone()),
        catalog: Some(catalog_arc.clone()),
        resolved_creds: Some(resolved_arc.clone()),
        oauth: None,
        agent_creds: Some(agent_creds.clone()),
        credential_sealing_key: Some(key.clone()),
        credential_secrets: Some(secrets.clone()),
        operational_log: None,
        operational_log_store: None,
        op_resolver: Some(op_resolver.clone()),
    };
    let admin = TestServer::new(build_router(uds));
    let agent = TestServer::new(build_app_full_with_phase_k(
        cfg_arc,
        Some(audit),
        resolved_arc,
        None,
        Some(bearer_dyn),
        Some(registrations.clone()),
        catalog_arc,
        None,
        Some(agent_creds.clone()),
        Some(key),
        Some(secrets.clone()),
        None,
        Some(op_resolver),
    ));

    Harness {
        _dir: dir,
        admin,
        agent,
        op_bearer,
        agent_bearer,
        agent_public_id: record.public_id,
        agent_id: record.id,
        op_calls,
        registrations,
        agent_creds,
        secrets,
        mock,
    }
}

impl Harness {
    fn override_url(&self, registration: &str) -> String {
        format!(
            "/admin/operator/agents/{}/credentials/{registration}",
            self.agent_public_id
        )
    }

    async fn expect_upstream(&self, route: &str, name: &str, value: &str) {
        Mock::given(method("GET"))
            .and(path(route))
            .and(header(name, value))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&self.mock)
            .await;
    }

    async fn proxy_get(&self, url: &str) -> axum_test::TestResponse {
        self.agent
            .get(url)
            .add_header("authorization", &self.agent_bearer)
            .await
    }
}

#[tokio::test]
async fn runtime_added_op_registration_resolves_without_restart() {
    let h = setup().await;
    let before = h.op_calls.load(Ordering::Relaxed);

    h.admin
        .put("/admin/operator/models/late-api")
        .add_header("authorization", &h.op_bearer)
        .json(&json!({
            "upstream": h.mock.uri(),
            "auth": { "kind": "op_bearer", "reference": LATE_REF },
        }))
        .await
        .assert_status_ok();
    assert_eq!(
        h.op_calls.load(Ordering::Relaxed),
        before + 1,
        "only the new reference is resolved; cached ones are not re-read"
    );

    h.expect_upstream("/late/ping", "authorization", "Bearer late-value")
        .await;
    let resp = h.proxy_get("/api/late-api/late/ping").await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn override_only_op_reference_resolves() {
    let h = setup().await;
    h.admin
        .put(&h.override_url("shared-api"))
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "auth_spec": { "kind": "op_bearer", "reference": OVERRIDE_REF } }))
        .await
        .assert_status_ok();

    h.expect_upstream("/shared/ping", "authorization", "Bearer override-op-value")
        .await;
    h.proxy_get("/api/shared-api/shared/ping")
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn clearing_stored_override_tombstones_its_sealed_value() {
    let h = setup().await;
    let body: serde_json::Value = h
        .admin
        .put(&format!("{}/credential", h.override_url("shared-api")))
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "override-secret" }))
        .await
        .json();
    let secret_ref = body["secret_ref"].as_str().unwrap().to_string();
    assert!(h.secrets.get(&secret_ref).await.unwrap().is_some());

    h.admin
        .delete(&h.override_url("shared-api"))
        .add_header("authorization", &h.op_bearer)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    assert!(
        h.secrets.get(&secret_ref).await.unwrap().is_none(),
        "clearing the override must tombstone its sealed value"
    );
}

#[tokio::test]
async fn stored_credential_on_seed_row_makes_it_operator_owned() {
    let h = setup().await;
    h.admin
        .put("/admin/operator/models/seed-api/credential")
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "operator-value" }))
        .await
        .assert_status_ok();
    let row = h.registrations.get("seed-api").await.unwrap().unwrap();
    assert!(
        !row.seed,
        "a seed refresh must not be able to overwrite an operator-set credential"
    );
}

#[tokio::test]
async fn stored_override_inherits_registration_header() {
    let h = setup().await;
    h.admin
        .put(&format!("{}/credential", h.override_url("hdr-api")))
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "hdr-secret" }))
        .await
        .assert_status_ok();

    let o = h
        .agent_creds
        .get(h.agent_id, "hdr-api")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(o.auth_spec.header_name(), Some("x-api-key"));

    h.expect_upstream("/hdr/ping", "x-api-key", "hdr-secret")
        .await;
    h.proxy_get("/api/hdr-api/hdr/ping")
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn stored_credential_on_op_header_registration_keeps_header() {
    let h = setup().await;
    h.admin
        .put("/admin/operator/models/ophdr-api/credential")
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "now-stored" }))
        .await
        .assert_status_ok();
    let row = h.registrations.get("ophdr-api").await.unwrap().unwrap();
    assert!(row.auth.is_stored());
    assert_eq!(row.auth.header_name(), Some("x-api-key"));
}

#[tokio::test]
async fn sealed_value_orphaned_by_generic_override_is_collected() {
    let h = setup().await;
    let body: serde_json::Value = h
        .admin
        .put(&format!("{}/credential", h.override_url("shared-api")))
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "soon-orphaned" }))
        .await
        .json();
    let secret_ref = body["secret_ref"].as_str().unwrap().to_string();

    // A generic override write replaces the stored override without an
    // explicit tombstone — the GC must catch it.
    h.admin
        .put(&h.override_url("shared-api"))
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "auth_spec": { "kind": "bearer", "env_var": "OTHER" } }))
        .await
        .assert_status_ok();
    assert!(h.secrets.get(&secret_ref).await.unwrap().is_some());

    assert_eq!(h.secrets.tombstone_unreferenced(i64::MAX).await.unwrap(), 1);
    assert!(h.secrets.get(&secret_ref).await.unwrap().is_none());
}
