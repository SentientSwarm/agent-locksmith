//! HTTP destinations are validated before operator/seed writes, without probing networks.
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{
    Kind, RegistrationError, RegistrationRepository, seed_loader, validate_upstream,
};
use serde_json::json;
use tempfile::TempDir;

#[test]
fn ordinary_http_destinations_and_infra_remain_compatible() {
    for url in [
        "https://chatgpt.com/backend-api/codex",
        "https://example.invalid/v2/",
        "http://localhost:8080",
        "http://127.0.0.1:8080/v1",
        "http://[::1]:8080/v1",
        "http://10.0.0.1/internal",
        "HTTPS://example.invalid/prefix",
    ] {
        for kind in [Kind::Tool, Kind::Model] {
            validate_upstream(kind, url).unwrap();
        }
    }
    for url in ["unix:///run/service.sock", "tcp://localhost:1234", ""] {
        validate_upstream(Kind::Infra, url).unwrap();
    }
}

#[test]
fn invalid_http_destinations_have_static_errors() {
    for url in [
        "",
        "not-a-url",
        "/relative",
        "https:example.invalid",
        "http:///example.invalid",
        "https://",
        "https:///",
        "ftp://example.invalid",
        "ws://example.invalid",
        "https://user:private@example.invalid",
        "http://@example.invalid",
        "https://example.invalid?key=private",
        "https://example.invalid#private",
        " https://example.invalid",
        "https://example.invalid/\nprivate",
        "http://example.invalid\\private",
    ] {
        for kind in [Kind::Tool, Kind::Model] {
            let error = validate_upstream(kind, url).unwrap_err();
            assert!(matches!(error, RegistrationError::InvalidUpstream));
            assert_eq!(
                error.to_string(),
                RegistrationError::InvalidUpstream.to_string()
            );
            assert!(!error.to_string().contains("private"));
        }
    }
}

fn catalog(version: &str, destinations: &[(&str, &str)]) -> String {
    let entries: Vec<_> = destinations.iter().map(|(name, upstream)| {
        json!({"name":name,"kind":"tool","upstream":upstream,"auth":{"kind":"none"}})
    }).collect();
    serde_json::to_string(&json!({"version":version,"entries":entries})).unwrap()
}

async fn fresh() -> (TempDir, RegistrationRepository) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("state.db"))
        .await
        .unwrap();
    (dir, RegistrationRepository::new(pool))
}

#[tokio::test]
async fn malformed_later_seed_leaves_earlier_rows_and_version_unchanged() {
    let (_dir, repo) = fresh().await;
    let original = catalog("1.0.0", &[("existing", "https://example.invalid/original")]);
    seed_loader::apply_catalog(&repo, &original).await.unwrap();
    let before = repo.list(None).await.unwrap();
    let invalid = catalog(
        "2.0.0",
        &[
            ("existing", "https://example.invalid/replacement"),
            ("new-valid", "https://example.invalid"),
            ("new-invalid", "https://example.invalid?key=private"),
        ],
    );
    let error = seed_loader::apply_catalog(&repo, &invalid)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        seed_loader::SeedLoadError::Entry {
            error: RegistrationError::InvalidUpstream,
            ..
        }
    ));
    assert!(!error.to_string().contains("private"));
    assert_eq!(repo.list(None).await.unwrap(), before);
    assert_eq!(
        repo.get_seed_version().await.unwrap().as_deref(),
        Some("1.0.0")
    );
}

#[tokio::test]
async fn malformed_initial_seed_writes_nothing() {
    let (_dir, repo) = fresh().await;
    let invalid = catalog(
        "1.0.0",
        &[
            ("new-valid", "https://example.invalid"),
            ("new-invalid", "not-a-url"),
        ],
    );
    assert!(seed_loader::apply_catalog(&repo, &invalid).await.is_err());
    assert!(repo.list(None).await.unwrap().is_empty());
    assert_eq!(repo.get_seed_version().await.unwrap(), None);
}
