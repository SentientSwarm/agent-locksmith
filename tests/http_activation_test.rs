//! Persisted authority, activation failure and the admission boundary.
use agent_locksmith::{
    app::build_app_full_with_phase_g,
    auth_v2::{AgentAuthenticator, AgentIdentity, AuthError, BearerAuthenticator},
    config::parse_config_str,
    migrations::open_and_migrate,
    registrations::{
        AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
        api::{self, AdminRegistrationsState},
    },
    repo::{AgentCredentialRepository, AgentRepository},
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::{extract::State, response::Response};
use axum_test::TestServer;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::sync::Arc;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

struct FrozenIdentity(AgentIdentity);
#[async_trait]
impl AgentAuthenticator for FrozenIdentity {
    async fn authenticate_bearer(&self, _: &str) -> Result<AgentIdentity, AuthError> {
        Ok(self.0.clone())
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    pool: sqlx::SqlitePool,
    agents: AgentRepository,
    bindings: AgentCredentialRepository,
    admin: AdminRegistrationsState,
    server: TestServer,
    identity: AgentIdentity,
    upstream: MockServer,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pool = open_and_migrate(&dir.path().join("db")).await.unwrap();
        let regs = Arc::new(RegistrationRepository::new(pool.clone()));
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("selected-account"))
            .mount(&upstream)
            .await;
        for name in ["service", "healthy"] {
            regs.create(&Registration::new(
                name.into(),
                Kind::Tool,
                "original".into(),
                upstream.uri(),
                AuthSpec::None,
            ))
            .await
            .unwrap();
        }
        let agents = AgentRepository::new(pool.clone());
        let (pid, secret) = agents
            .create(
                "caller",
                None,
                Some(&["service".into(), "healthy".into()]),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let identity = BearerAuthenticator::new(agents.clone())
            .unwrap()
            .authenticate_bearer(&format!("Bearer lk_{pid}.{}", secret.expose_secret()))
            .await
            .unwrap();
        let bindings = AgentCredentialRepository::new(pool.clone());
        for name in ["service", "healthy"] {
            bindings
                .set(identity.id, name, &AuthSpec::None)
                .await
                .unwrap();
        }
        let catalog = Arc::new(ArcSwap::from_pointee(
            Catalog::from_repo(&regs).await.unwrap(),
        ));
        // Same-name YAML deliberately exists: DB absence/disable/staleness must not use it.
        let cfg = parse_config_str(&format!("listen:\n  port: 9200\ntools:\n  - name: service\n    description: legacy\n    upstream: {}\n", upstream.uri())).unwrap();
        let resolved = Arc::new(ArcSwap::from_pointee(Default::default()));
        let server = TestServer::new(build_app_full_with_phase_g(
            Arc::new(ArcSwap::from_pointee(cfg)),
            None,
            resolved.clone(),
            None,
            Some(Arc::new(FrozenIdentity(identity.clone()))),
            Some(regs.clone()),
            catalog.clone(),
            None,
            Some(bindings.clone()),
        ));
        let admin = AdminRegistrationsState {
            local_listener: None,
            repo: regs,
            catalog: Some(catalog),
            resolved_creds: Some(resolved),
            credential_sealing_key: None,
            credential_secrets: None,
            operational_log: None,
            op_resolver: None,
            agent_creds: Some(bindings.clone()),
        };
        Self {
            _dir: dir,
            pool,
            agents,
            bindings,
            admin,
            server,
            identity,
            upstream,
        }
    }
    async fn get(&self, name: &str) -> axum_test::TestResponse {
        self.server
            .get(&format!("/api/{name}/check"))
            .add_header("authorization", "Bearer fixture")
            .await
    }
    async fn denied(&self, status: u16, code: &str) {
        let before = self.upstream.received_requests().await.unwrap().len();
        let response = self.get("service").await;
        assert_eq!(response.status_code().as_u16(), status);
        assert_eq!(response.json::<Value>()["error"]["code"], code);
        assert_eq!(
            self.upstream.received_requests().await.unwrap().len(),
            before
        );
    }
}
async fn body(response: Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 100000)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn listing(f: &Fixture) -> Vec<Value> {
    api::list_public(
        &f.admin.repo,
        &f.admin.catalog.as_ref().unwrap().load(),
        Kind::Tool,
        Some(&f.identity),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn metadata_only_change_preserves_authority_and_requires_activation() {
    let f = Fixture::new().await;
    let mut row = f.admin.repo.get("service").await.unwrap().unwrap();
    row.metadata =
        serde_json::from_str(include_str!("../examples/http-service-reference.json")).unwrap();
    row.metadata["private"] = json!("private-marker");
    f.admin.repo.upsert(&row).await.unwrap();
    f.denied(503, "connection_not_active").await;
    let stale = listing(&f).await;
    assert!(!stale.iter().any(|v| v["name"] == "service"));
    f.admin.refresh_runtime().await.unwrap();
    f.get("service").await.assert_status_ok();
    let active = listing(&f).await;
    let service = active.iter().find(|v| v["name"] == "service").unwrap();
    assert_eq!(service["http_service"]["version"], 1);
    assert_eq!(service["account_selected"], true);
    assert_eq!(service["credential_readiness"], "not_checked");
    assert!(!service.to_string().contains("private-marker"));
}

#[tokio::test]
async fn malformed_preexisting_descriptor_is_omitted_from_discovery() {
    let f = Fixture::new().await;
    let mut row = f.admin.repo.get("service").await.unwrap().unwrap();
    row.metadata = json!({"http_service":{"private":"private-marker"},"other":"private-marker"});
    f.admin.repo.upsert(&row).await.unwrap();
    f.admin.refresh_runtime().await.unwrap();
    let items = listing(&f).await;
    let service = items.iter().find(|v| v["name"] == "service").unwrap();
    assert!(service.get("http_service").is_none());
    assert!(!service.to_string().contains("private-marker"));
    f.get("service").await.assert_status_ok();
}

#[tokio::test]
async fn persisted_write_failed_activation_denies_changed_row_and_recovers() {
    let f = Fixture::new().await;
    f.get("service").await.assert_status_ok();
    let mut poison = f.admin.repo.get("healthy").await.unwrap().unwrap();
    poison.name = "poison".into();
    f.admin.repo.create(&poison).await.unwrap();
    sqlx::query("UPDATE registrations SET auth_json='invalid' WHERE name='poison'")
        .execute(&f.pool)
        .await
        .unwrap();
    let write = api::op_put(
        State(f.admin.clone()),
        Kind::Tool,
        "service".into(),
        serde_json::from_value(json!({
            "upstream": f.upstream.uri(), "description":"changed", "auth":{"kind":"none"}
        }))
        .unwrap(),
    )
    .await;
    assert_eq!(write.status(), 503);
    let saved = body(write).await;
    assert_eq!(saved["saved"], true);
    assert_eq!(saved["activation"], "failed");
    assert_eq!(
        f.admin
            .repo
            .get("service")
            .await
            .unwrap()
            .unwrap()
            .description,
        "changed"
    );
    f.denied(503, "connection_not_active").await;
    f.get("healthy").await.assert_status_ok();
    let read = body(api::op_get(State(f.admin.clone()), Kind::Tool, "service".into()).await).await;
    assert_eq!(read["activation"], "pending");
    assert_eq!(read["credential_readiness"], "not_checked");
    // The unrelated malformed row cannot hide healthy entries, and changed
    // entries are omitted until their full runtime configuration matches.
    let catalog = f
        .server
        .get("/tools")
        .add_header("authorization", "Bearer fixture")
        .await
        .json::<Value>();
    assert_eq!(catalog["tools"].as_array().unwrap().len(), 1);
    assert_eq!(catalog["tools"][0]["name"], "healthy");
    let skill = f
        .server
        .get("/skill")
        .add_header("authorization", "Bearer fixture")
        .await
        .text();
    assert!(!skill.contains("`service`"));
    f.admin.repo.delete("poison").await.unwrap();
    f.admin.refresh_runtime().await.unwrap();
    f.get("service").await.assert_status_ok();
    let read = body(api::op_get(State(f.admin.clone()), Kind::Tool, "service".into()).await).await;
    assert_eq!(read["activation"], "active");
    assert_eq!(read["credential_readiness"], "not_checked");
}

#[tokio::test]
async fn admission_rechecks_policy_lifecycle_and_binding_after_authentication() {
    let f = Fixture::new().await;
    f.get("service").await.assert_status_ok();
    // Frozen authenticator models a request authenticated before each committed change.
    f.bindings.delete(f.identity.id, "service").await.unwrap();
    f.denied(403, "tool_not_allowed").await;
    f.bindings
        .set(f.identity.id, "service", &AuthSpec::None)
        .await
        .unwrap();
    f.agents
        .update_policy(
            &f.identity.public_id,
            Some(Some(vec!["healthy".into()])),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    f.denied(403, "tool_not_allowed").await;
    f.agents
        .update_policy(
            &f.identity.public_id,
            Some(Some(vec!["service".into(), "healthy".into()])),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    f.get("service").await.assert_status_ok();
    f.agents
        .update_policy(&f.identity.public_id, None, None, None, Some(Some(1)))
        .await
        .unwrap();
    f.denied(401, "invalid_credential").await;
    f.agents
        .update_policy(&f.identity.public_id, None, None, None, Some(None))
        .await
        .unwrap();
    f.agents.revoke(&f.identity.public_id).await.unwrap();
    f.denied(401, "invalid_credential").await;
}

#[tokio::test]
async fn database_disable_delete_and_replacement_never_use_same_name_yaml() {
    let f = Fixture::new().await;
    f.admin.repo.set_disabled("service", true).await.unwrap();
    f.denied(404, "tool_not_found").await;
    f.admin.repo.set_disabled("service", false).await.unwrap();
    // Same contents are active again; change destination without refreshing.
    let mut changed = f.admin.repo.get("service").await.unwrap().unwrap();
    changed.upstream = "http://127.0.0.1:9".into();
    f.admin.repo.upsert(&changed).await.unwrap();
    f.denied(403, "tool_not_allowed").await;
    f.agents
        .update_policy(
            &f.identity.public_id,
            Some(Some(vec!["service".into()])),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    f.bindings
        .set(f.identity.id, "service", &AuthSpec::None)
        .await
        .unwrap();
    f.denied(503, "connection_not_active").await;
    f.admin.repo.delete("service").await.unwrap();
    f.denied(404, "tool_not_found").await;
}
