use agent_locksmith::{
    migrations::open_and_migrate,
    registrations::{AuthSpec, Kind, Registration, RegistrationRepository, api::PutBody},
};
use serde_json::json;

#[test]
fn typed_native_operator_input_is_supported() {
    let body = json!({"upstream":"https://example.com/mcp", "auth":{"kind":"none"},
        "protocol":"mcp_streamable_http", "mcp":{"protocol_version":"2025-11-25"}});
    assert!(serde_json::from_value::<PutBody>(body).is_ok());
}

#[tokio::test]
async fn migration_preserves_http_and_creates_no_native_connections() {
    let dir = tempfile::tempdir().unwrap();
    let pool = open_and_migrate(&dir.path().join("state.db"))
        .await
        .unwrap();
    let repo = RegistrationRepository::new(pool.clone());
    let r = Registration::new(
        "http".into(),
        Kind::Tool,
        String::new(),
        "https://example.com".into(),
        AuthSpec::None,
    );
    repo.create(&r).await.unwrap();
    let protocols: Vec<String> = sqlx::query_scalar("SELECT protocol FROM registrations")
        .fetch_all(&pool)
        .await
        .expect("real native migration must define protocol");
    assert_eq!(protocols, ["http"]);
    assert_eq!(repo.get("http").await.unwrap(), Some(r));
}
