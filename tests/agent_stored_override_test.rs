//! Phase J / M2 (WEM-445, CCS-7) — per-agent stored-credential override.
//!
//! `PUT /admin/operator/agents/{public_id}/credentials/{registration}/credential`
//! seals an operator value into `credential_secrets` and writes a
//! `stored_*` per-agent override. End-to-end:
//!   1. operator sets a stored override for an agent on a registration;
//!   2. the override auth is `stored_bearer` with a `cs_` ref (no value);
//!   3. the agent proxies through and the upstream sees the injected,
//!      unsealed value — proving the override drives the hot path.
//!
//! Admin (UdsState) and proxy (AppState) share one pool + catalog +
//! resolved-creds + credential key + sealed store + agent-override repo,
//! exactly like the production daemon wiring.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::app::build_app_full_with_phase_k;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{Catalog, Kind, Registration, RegistrationRepository};
use agent_locksmith::repo::{
    AgentCredentialRepository, AgentRepository, BootstrapTokenRepository,
    CredentialSecretsRepository,
};
use agent_locksmith::registrations::AuthSpec;
use agent_locksmith::secret::CredentialSealingKey;
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct E2E {
    _dir: TempDir,
    admin: TestServer,
    agent: TestServer,
    op_bearer: String,
    agent_bearer: String,
    agent_public_id: String,
    agent_creds: AgentCredentialRepository,
    agent_id: i64,
    mock: MockServer,
}

async fn setup() -> E2E {
    let dir = TempDir::new().unwrap();

    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_bearer = format!("Bearer {}", op_token.wire_format());
    let token_hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_token.secret.expose().to_string(),
    ))
    .unwrap();
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
    let audit = agent_locksmith::repo::audit::AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let secrets = CredentialSecretsRepository::new(pool.clone());
    let agent_creds = AgentCredentialRepository::new(pool.clone());
    let key = CredentialSealingKey::generate().unwrap();

    let mock = MockServer::start().await;

    // Authless registration; the per-agent override supplies the credential.
    let r = Registration::new(
        "shared-api".to_string(),
        Kind::Model,
        "Shared API (test)".to_string(),
        mock.uri(),
        AuthSpec::None,
    );
    registrations.create(&r).await.unwrap();

    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));
    let resolved_arc = Arc::new(ArcSwap::from_pointee(Default::default()));

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\ntools: []\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    let (pid, secret) = agents
        .create(
            "agent-1",
            None,
            Some(&["shared-api".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let agent_bearer = format!("Bearer lk_{pid}.{}", secret.expose_secret());
    let agent_rec = agents.get_by_name("agent-1").await.unwrap().unwrap();
    let agent_id = agent_rec.id;
    let agent_public_id = agent_rec.public_id.clone();

    let bearer_concrete =
        Arc::new(BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap());
    let bearer_dyn: Arc<dyn AgentAuthenticator> = bearer_concrete.clone();
    let operator_auth = Arc::new(OperatorAuthenticator::load(&ops_path).unwrap());
    let admin_service = Arc::new(AdminService::new(agents, bootstrap, cfg_arc.clone()));

    // Admin router.
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
    };
    let admin = TestServer::new(build_router(uds));

    // Agent / proxy router over the SAME substrate.
    let agent_router = build_app_full_with_phase_k(
        cfg_arc,
        Some(audit),
        resolved_arc,
        None,
        Some(bearer_dyn),
        Some(registrations),
        catalog_arc,
        None,
        Some(agent_creds.clone()),
        Some(key),
        Some(secrets),
        None,
        None,
    );
    let agent = TestServer::new(agent_router);

    E2E {
        _dir: dir,
        admin,
        agent,
        op_bearer,
        agent_bearer,
        agent_public_id,
        agent_creds,
        agent_id,
        mock,
    }
}

#[tokio::test]
async fn per_agent_stored_override_injects_on_proxy() {
    let h = setup().await;

    // 1. Operator sets a stored bearer override for the agent on shared-api.
    let set: serde_json::Value = h
        .admin
        .put(&format!(
            "/admin/operator/agents/{}/credentials/shared-api/credential",
            h.agent_public_id
        ))
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "per-agent-secret-xyz" }))
        .await
        .json();
    let secret_ref = set["secret_ref"].as_str().unwrap().to_string();
    assert!(secret_ref.starts_with("cs_"), "ref: {secret_ref}");

    // 2. The override row is stored_bearer with that cs_ ref — no value.
    let override_row = h
        .agent_creds
        .get(h.agent_id, "shared-api")
        .await
        .unwrap()
        .unwrap();
    match override_row.auth_spec {
        AuthSpec::StoredBearer { secret_ref: r } => assert_eq!(r, secret_ref),
        other => panic!("expected stored_bearer, got {other:?}"),
    }

    // 3. Agent proxies through → upstream sees the unsealed injected value.
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer per-agent-secret-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .mount(&h.mock)
        .await;

    let resp = h
        .agent
        .get("/api/shared-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "pong");
}

#[tokio::test]
async fn stored_override_with_header_makes_stored_header() {
    let h = setup().await;

    h.admin
        .put(&format!(
            "/admin/operator/agents/{}/credentials/shared-api/credential",
            h.agent_public_id
        ))
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "header-secret", "header": "x-api-key" }))
        .await
        .assert_status_ok();

    let override_row = h
        .agent_creds
        .get(h.agent_id, "shared-api")
        .await
        .unwrap()
        .unwrap();
    match override_row.auth_spec {
        AuthSpec::StoredHeader { header, .. } => assert_eq!(header, "x-api-key"),
        other => panic!("expected stored_header, got {other:?}"),
    }
}
