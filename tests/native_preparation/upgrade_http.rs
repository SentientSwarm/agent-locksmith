use super::fixture::Fixture;
use agent_locksmith::{
    registrations::AuthSpec,
    repo::{AgentCredentialRepository, AgentRepository, CredentialSecretsRepository},
    secret::CredentialSealingKey,
};
use serde_json::Value;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};
pub const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

pub async fn setup(f: &Fixture) -> (MockServer, Value) {
    let receiver = receiver().await;
    let agent = prepare(f, &receiver).await;
    (receiver, agent)
}
async fn receiver() -> MockServer {
    let receiver = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/check"))
        .and(header("Authorization", "Bearer synthetic-persisted"))
        .respond_with(ResponseTemplate::new(200).set_body_string("account-x"))
        .mount(&receiver)
        .await;
    receiver
}
async fn prepare(f: &Fixture, receiver: &MockServer) -> Value {
    f.op(&[
        "tool",
        "put",
        "existing-http",
        "--upstream",
        &receiver.uri(),
        "--auth",
        "none",
        "--egress",
        "direct",
    ]);
    let agent = f.op(&[
        "agent",
        "register",
        "--name",
        "existing-http",
        "--allowlist",
        "existing-http",
    ]);
    bind(f).await;
    allowed(f, &agent).await;
    agent
}
async fn bind(f: &Fixture) {
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db")),
    )
    .await
    .unwrap();
    let row = AgentRepository::new(pool.clone())
        .get_by_name("existing-http")
        .await
        .unwrap()
        .unwrap();
    let key = CredentialSealingKey::from_b64(KEY).unwrap();
    let (sealed, nonce) = key.seal(b"synthetic-persisted").unwrap();
    let secret_ref = CredentialSecretsRepository::new(pool.clone())
        .insert(&sealed, &nonce)
        .await
        .unwrap();
    AgentCredentialRepository::new(pool.clone())
        .set(
            row.id,
            "existing-http",
            &AuthSpec::StoredBearer { secret_ref },
        )
        .await
        .unwrap();
    pool.close().await;
}
pub async fn allowed(f: &Fixture, agent: &Value) {
    let r = f
        .http
        .get(f.url("/api/existing-http/check"))
        .bearer_auth(agent["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "account-x");
}
