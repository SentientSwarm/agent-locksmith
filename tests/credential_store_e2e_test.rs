//! Phase J (WEM-441, CCS-1..6) — M1 end-to-end slice for the `stored`
//! custody backend. `op` (1Password) is uninstalled / irrelevant: the whole
//! flow runs against locksmith's own sealed `credential_secrets` store.
//!
//! One test proves the full slice:
//!   1. an operator sets a stored bearer via the admin API;
//!   2. an agent proxies through and the mock upstream sees the correctly
//!      injected `Authorization: Bearer <value>`;
//!   3. an admin registration read shows the stored shape + set_at and
//!      NEVER the value (reveal-never, CCS-1/CCS-4);
//!   4. rotating (set again) tombstones the old sealed row;
//!   5. the stored route 404s when LOCKSMITH_CREDENTIAL_SEALING_KEY is unset.
//!
//! The admin router (UdsState) and the agent/proxy router (AppState) share
//! one SQLite pool, catalog `ArcSwap`, resolved-creds map, credential key,
//! and sealed store, so an admin write is visible to the proxy hot path
//! without a restart — exactly the production daemon wiring.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::app::build_app_full_with_phase_j;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{Catalog, RegistrationRepository};
use agent_locksmith::repo::{
    AgentRepository, BootstrapTokenRepository, CredentialSecretsRepository,
};
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
    secrets: CredentialSecretsRepository,
    mock: MockServer,
}

/// Stand up admin + proxy routers over one shared substrate. `wire_key`
/// toggles the sealing key + sealed store into BOTH routers so the
/// "feature off ⇒ 404" gate can be exercised end to end.
async fn setup(wire_key: bool) -> E2E {
    let dir = TempDir::new().unwrap();

    // Operator credential file.
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
    let key = CredentialSealingKey::generate().unwrap();

    let mock = MockServer::start().await;

    // Shared runtime state observed by BOTH routers.
    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));
    let resolved_arc = Arc::new(ArcSwap::from_pointee(Default::default()));

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\ntools: []\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    // Agent allowed to call `store-api`.
    let (pid, secret) = agents
        .create(
            "agent-1",
            None,
            Some(&["store-api".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let agent_bearer = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    let bearer_concrete =
        Arc::new(BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap());
    let bearer_dyn: Arc<dyn AgentAuthenticator> = bearer_concrete.clone();
    let operator_auth = Arc::new(OperatorAuthenticator::load(&ops_path).unwrap());
    let admin_service = Arc::new(AdminService::new(agents, bootstrap, cfg_arc.clone()));

    let (app_key, app_secrets) = if wire_key {
        (Some(key.clone()), Some(secrets.clone()))
    } else {
        (None, None)
    };

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
        agent_creds: None,
        credential_sealing_key: app_key.clone(),
        credential_secrets: app_secrets.clone(),
        operational_log: None,
    };
    let admin = TestServer::new(build_router(uds));

    // Agent / proxy router over the SAME catalog + resolved-creds + store.
    let agent_router = build_app_full_with_phase_j(
        cfg_arc,
        Some(audit),
        resolved_arc,
        None,
        Some(bearer_dyn),
        Some(registrations),
        catalog_arc,
        None,
        None,
        app_key,
        app_secrets,
    );
    let agent = TestServer::new(agent_router);

    E2E {
        _dir: dir,
        admin,
        agent,
        op_bearer,
        agent_bearer,
        secrets,
        mock,
    }
}

#[tokio::test]
async fn full_stored_credential_slice_without_op() {
    let h = setup(true).await;

    // 1. Operator registers `store-api` (kind=model, authless) then sets a
    //    stored bearer value via the admin API.
    h.admin
        .put("/admin/operator/models/store-api")
        .add_header("authorization", &h.op_bearer)
        .json(&json!({
            "upstream": h.mock.uri(),
            "auth": { "kind": "none" },
        }))
        .await
        .assert_status_ok();

    let set: serde_json::Value = h
        .admin
        .put("/admin/operator/models/store-api/credential")
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "e2e-live-secret" }))
        .await
        .json();
    let first_ref = set["secret_ref"].as_str().unwrap().to_string();
    assert!(first_ref.starts_with("cs_"));
    assert!(set["set_at"].as_i64().unwrap() > 0);

    // 2. Agent proxies through → upstream sees the injected bearer.
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer e2e-live-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .mount(&h.mock)
        .await;

    let resp = h
        .agent
        .get("/api/store-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "pong");

    // 3. Admin read shows the stored shape + no value (reveal-never).
    let reg: serde_json::Value = h
        .admin
        .get("/admin/operator/models/store-api")
        .add_header("authorization", &h.op_bearer)
        .await
        .json();
    assert_eq!(reg["auth"]["kind"], "stored_bearer");
    assert_eq!(reg["auth"]["secret_ref"], first_ref);
    assert!(reg["auth"].get("value").is_none());
    assert!(reg["updated_at"].as_i64().unwrap() > 0);

    // 4. Rotate: set again → new ref, old row tombstoned.
    let rot: serde_json::Value = h
        .admin
        .put("/admin/operator/models/store-api/credential")
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "e2e-rotated-secret" }))
        .await
        .json();
    let second_ref = rot["secret_ref"].as_str().unwrap().to_string();
    assert_ne!(first_ref, second_ref);
    assert!(h.secrets.get(&first_ref).await.unwrap().is_none());
    assert!(h.secrets.get(&second_ref).await.unwrap().is_some());

    // The proxy now injects the rotated value (shared catalog refreshed).
    Mock::given(method("GET"))
        .and(path("/v1/pong"))
        .and(header("authorization", "Bearer e2e-rotated-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("rotated-ok"))
        .mount(&h.mock)
        .await;
    let resp2 = h
        .agent
        .get("/api/store-api/v1/pong")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp2.assert_status_ok();
    assert_eq!(resp2.text(), "rotated-ok");
}

#[tokio::test]
async fn stored_route_404s_when_sealing_key_unset() {
    // 5. Feature off: the daemon booted without LOCKSMITH_CREDENTIAL_SEALING_KEY.
    let h = setup(false).await;

    h.admin
        .put("/admin/operator/models/store-api")
        .add_header("authorization", &h.op_bearer)
        .json(&json!({
            "upstream": h.mock.uri(),
            "auth": { "kind": "none" },
        }))
        .await
        .assert_status_ok();

    let resp = h
        .admin
        .put("/admin/operator/models/store-api/credential")
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": "wont-store" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}
