use super::fixture::*;
use agent_locksmith::{
    app::build_app_full_with_phase_j,
    auth_v2::BearerAuthenticator,
    config::parse_config_str,
    migrations::open_and_migrate,
    registrations::{AuthSpec, Catalog, RegistrationRepository},
    repo::{AgentCredentialRepository, AgentRepository, CredentialSecretsRepository},
    secret::CredentialSealingKey,
};
use arc_swap::ArcSwap;
use axum_test::{TestResponse, TestServer};
use sqlx::SqlitePool;
use std::sync::Arc;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method},
};

async fn seal(pool: &SqlitePool, key: &CredentialSealingKey, bytes: &[u8]) -> AuthSpec {
    let (ct, nonce) = key.seal(bytes).unwrap();
    let secret_ref = CredentialSecretsRepository::new(pool.clone())
        .insert(&ct, &nonce)
        .await
        .unwrap();
    AuthSpec::StoredBearer { secret_ref }
}
async fn accounts() -> MockServer {
    let mock = MockServer::start().await;
    for (value, account) in [("PRIVATE_STORED_X", "X"), ("PRIVATE_STORED_Y", "Y")] {
        Mock::given(method("GET"))
            .and(header("authorization", format!("Bearer {value}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(account))
            .mount(&mock)
            .await;
    }
    mock
}
async fn prepare(f: &Fixture, mock: &MockServer, key: &CredentialSealingKey) {
    let mut registration = f.registrations.get("api").await.unwrap().unwrap();
    registration.upstream = mock.uri();
    registration.auth = seal(&f.pool, key, b"PRIVATE_STORED_X").await;
    f.registrations.upsert(&registration).await.unwrap();
    f.bindings
        .set(
            f.ids[2],
            "api",
            &seal(&f.pool, key, b"PRIVATE_STORED_Y").await,
        )
        .await
        .unwrap();
}
pub(super) async fn application(pool: &SqlitePool, key: &CredentialSealingKey) -> TestServer {
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let catalog = Catalog::from_repo(&registrations).await.unwrap();
    TestServer::new(build_app_full_with_phase_j(
        Arc::new(ArcSwap::from_pointee(
            parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap(),
        )),
        None,
        Arc::new(ArcSwap::from_pointee(Default::default())),
        None,
        Some(Arc::new(
            BearerAuthenticator::new(AgentRepository::new(pool.clone())).unwrap(),
        )),
        Some(registrations),
        Arc::new(ArcSwap::from_pointee(catalog)),
        None,
        Some(AgentCredentialRepository::new(pool.clone())),
        Some(key.clone()),
        Some(CredentialSecretsRepository::new(pool.clone())),
    ))
}
pub(super) async fn call(
    server: &TestServer,
    f: &Fixture,
    index: usize,
    name: &str,
) -> TestResponse {
    server
        .get(&format!("/api/{name}/check"))
        .add_header("authorization", &f.bearers[index])
        .await
}
async fn positive(server: &TestServer, f: &Fixture, mock: &MockServer) {
    for (i, expected) in ["X", "X", "Y"].into_iter().enumerate() {
        let response = call(server, f, i, "api").await;
        response.assert_status_ok();
        assert_eq!(response.text(), expected);
    }
    assert_eq!(mock.received_requests().await.unwrap().len(), 3);
}
async fn denied(
    server: &TestServer,
    f: &Fixture,
    mock: &MockServer,
    index: usize,
    name: &str,
    status: u16,
    code: &str,
) {
    let before = mock.received_requests().await.unwrap().len();
    let response = call(server, f, index, name).await;
    assert_eq!(response.status_code().as_u16(), status);
    assert_eq!(response.json::<serde_json::Value>()["error"]["code"], code);
    assert_eq!(mock.received_requests().await.unwrap().len(), before);
}
#[tokio::test]
async fn migrated_shared_x_x_distinct_y_persist_and_unmapped_sources_never_dispatch() {
    let f = Fixture::new().await;
    let mock = accounts().await;
    let key = CredentialSealingKey::generate().unwrap();
    let pool = migrate(&f, &mock, &key).await;
    let server = application(&pool, &key).await;
    positive(&server, &f, &mock).await;
    denied(&server, &f, &mock, 3, "api", 403, "tool_not_allowed").await;
    tombstone_shared(&pool, &f).await;
    denied(&server, &f, &mock, 0, "api", 503, "credential_unresolved").await;
    denied(&server, &f, &mock, 1, "api", 503, "credential_unresolved").await;
    let response = call(&server, &f, 2, "api").await;
    assert_eq!(response.text(), "Y");
    assert_eq!(mock.received_requests().await.unwrap().len(), 4);
}

async fn migrate(f: &Fixture, mock: &MockServer, key: &CredentialSealingKey) -> SqlitePool {
    prepare(f, mock, key).await;
    let mut plan = f.preview();
    for id in &f.ids[..2] {
        select(&mut plan, *id);
    }
    success(&f.apply(&plan));
    review_grants(f).await;
    f.pool.close().await;
    open_and_migrate(&f.db).await.unwrap()
}
async fn tombstone_shared(pool: &SqlitePool, f: &Fixture) {
    let AuthSpec::StoredBearer { secret_ref } = AgentCredentialRepository::new(pool.clone())
        .get(f.ids[0], "api")
        .await
        .unwrap()
        .unwrap()
        .auth_spec
    else {
        panic!("stored selection")
    };
    CredentialSecretsRepository::new(pool.clone())
        .tombstone(&secret_ref)
        .await
        .unwrap();
}
#[tokio::test]
async fn changed_template_and_future_entries_cannot_change_migrated_accounts() {
    let f = Fixture::new().await;
    let mock = accounts().await;
    let key = CredentialSealingKey::generate().unwrap();
    let pool = migrate(&f, &mock, &key).await;
    future_template(&pool, &key).await;
    let server = application(&pool, &key).await;
    positive(&server, &f, &mock).await;
    denied(&server, &f, &mock, 0, "future", 403, "tool_not_allowed").await;
    denied(&server, &f, &mock, 3, "api", 403, "tool_not_allowed").await;
    sqlx::query("UPDATE agents SET revoked_at=1 WHERE name='shared-b'")
        .execute(&pool)
        .await
        .unwrap();
    denied(&server, &f, &mock, 1, "api", 401, "invalid_credential").await;
}
async fn future_template(pool: &SqlitePool, key: &CredentialSealingKey) {
    let registrations = RegistrationRepository::new(pool.clone());
    let mut r = registrations.get("api").await.unwrap().unwrap();
    r.auth = seal(pool, key, b"PRIVATE_STORED_Y").await;
    registrations.upsert(&r).await.unwrap();
    r.name = "future".into();
    registrations.create(&r).await.unwrap();
}

pub(super) async fn review_grants(f: &Fixture) {
    let mut plan = agent_locksmith::binding_migration::preview_grants(&f.db, None)
        .await
        .unwrap();
    for grant in &mut plan.grants {
        grant.selected = true;
    }
    agent_locksmith::binding_migration::apply(&f.db, &plan, None)
        .await
        .unwrap();
}
