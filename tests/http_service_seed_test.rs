use agent_locksmith::{
    migrations::open_and_migrate,
    registrations::{RegistrationRepository, seed_loader},
};
use serde_json::{Value, json};

fn entry(name: &str, metadata: Value) -> Value {
    json!({"name":name,"kind":"tool","upstream":"https://example.invalid",
        "auth":{"kind":"none"},"metadata":metadata})
}

fn catalog(version: &str, entries: Vec<Value>) -> String {
    json!({"version":version,"entries":entries}).to_string()
}

async fn fresh() -> (tempfile::TempDir, RegistrationRepository) {
    let dir = tempfile::tempdir().unwrap();
    let pool = open_and_migrate(&dir.path().join("db")).await.unwrap();
    (dir, RegistrationRepository::new(pool))
}

#[tokio::test]
async fn malformed_later_descriptor_preserves_seed_rows_and_version() {
    let (_dir, repo) = fresh().await;
    let initial = catalog("1.0.0", vec![entry("existing", json!({"legacy":true}))]);
    seed_loader::apply_catalog(&repo, &initial).await.unwrap();
    let before = repo.list(None).await.unwrap();
    let candidate = catalog(
        "2.0.0",
        vec![
            entry("existing", json!({"changed":true})),
            entry("new-valid", json!({})),
            entry(
                "new-invalid",
                json!({"http_service":{"mode":"private-marker"}}),
            ),
        ],
    );
    let error = seed_loader::apply_catalog(&repo, &candidate)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("private-marker"));
    assert_eq!(repo.list(None).await.unwrap(), before);
    assert_eq!(
        repo.get_seed_version().await.unwrap().as_deref(),
        Some("1.0.0")
    );
}

#[tokio::test]
async fn seed_accepts_typed_descriptor_and_legacy_metadata_shapes() {
    let (_dir, repo) = fresh().await;
    let example: Value =
        serde_json::from_str(include_str!("../examples/http-service-reference.json")).unwrap();
    let seed = catalog(
        "1.0.0",
        vec![
            entry("typed", example.clone()),
            entry("old-string", json!("historical")),
            entry("old-array", json!([1, 2])),
        ],
    );
    seed_loader::apply_catalog(&repo, &seed).await.unwrap();
    assert_eq!(repo.get("typed").await.unwrap().unwrap().metadata, example);
    assert_eq!(
        repo.get("old-string").await.unwrap().unwrap().metadata,
        json!("historical")
    );
    assert_eq!(
        repo.get("old-array").await.unwrap().unwrap().metadata,
        json!([1, 2])
    );
}
