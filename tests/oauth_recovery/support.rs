pub use agent_locksmith::{
    migrations,
    oauth::{OauthSessionRepository, SealingKey, refresh::refresh_selected_session},
    registrations::AuthSpec,
};
pub use std::time::Duration;
pub use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

pub async fn held_provider() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&server)
        .await;
    server
}

pub async fn seed(
    repo: &OauthSessionRepository,
    key: &SealingKey,
) -> agent_locksmith::oauth::OauthSession {
    repo.create(
        key,
        "fixture",
        "reader",
        "synthetic-refresh",
        Some("synthetic-old-access"),
        Some(i64::MAX),
        "read",
    )
    .await
    .unwrap()
}

pub fn selection(server: &MockServer) -> AuthSpec {
    AuthSpec::OauthDeviceCode {
        client_id: "synthetic-client".into(),
        device_url: format!("{}/device", server.uri()),
        token_url: format!("{}/token", server.uri()),
        scopes: vec![],
        session_label: Some("reader".into()),
    }
}

pub async fn wait_arrival(server: &MockServer) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("observed token endpoint arrival");
}
