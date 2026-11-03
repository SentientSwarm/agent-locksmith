use super::*;
use crate::{
    migrations::open_and_migrate,
    repo::{AgentCredentialRepository, AgentRepository},
};

fn spec(endpoint: &str) -> AuthSpec {
    AuthSpec::OauthDeviceCode {
        client_id: "selected-client".into(),
        scopes: vec![],
        device_url: "http://127.0.0.1/device".into(),
        token_url: endpoint.into(),
        session_label: Some("selected".into()),
    }
}

async fn fixture() -> (
    tempfile::TempDir,
    AgentCredentialRepository,
    OauthSession,
    Vec<i64>,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("selection.db"))
        .await
        .unwrap();
    crate::registrations::RegistrationRepository::new(pool.clone())
        .create(&crate::registrations::Registration::new(
            "api".into(),
            crate::registrations::Kind::Tool,
            "fixture".into(),
            "http://127.0.0.1:1".into(),
            crate::registrations::AuthSpec::None,
        ))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let mut ids = Vec::new();
    for name in ["one", "two"] {
        agents
            .create(name, None, None, None, None, None)
            .await
            .unwrap();
        ids.push(agents.get_by_name(name).await.unwrap().unwrap().id);
    }
    let session = OauthSessionRepository::new(pool.clone())
        .create(
            &SealingKey::generate().unwrap(),
            "api",
            "selected",
            "private-refresh",
            Some("expired"),
            Some(0),
            "",
        )
        .await
        .unwrap();
    (dir, AgentCredentialRepository::new(pool), session, ids)
}

#[tokio::test]
async fn background_selection_requires_consistent_explicit_metadata() {
    let (_dir, bindings, session, ids) = fixture().await;
    assert!(
        selected_source(&bindings, &session.name, &session.session_label)
            .await
            .unwrap()
            .is_none()
    );
    let chosen = spec("http://127.0.0.1/selected-token");
    bindings.set(ids[0], "api", &chosen).await.unwrap();
    assert_eq!(
        selected_source(&bindings, &session.name, &session.session_label)
            .await
            .unwrap(),
        Some(chosen.clone())
    );
    bindings.set(ids[1], "api", &chosen).await.unwrap();
    assert_eq!(
        selected_source(&bindings, &session.name, &session.session_label)
            .await
            .unwrap(),
        Some(chosen)
    );
    bindings
        .set(ids[1], "api", &spec("http://127.0.0.1/other-token"))
        .await
        .unwrap();
    assert!(
        selected_source(&bindings, &session.name, &session.session_label)
            .await
            .is_err()
    );
}
