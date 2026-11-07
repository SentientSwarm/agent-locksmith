use super::fixture::{Fixture, definition, instance};
use agent_locksmith::registrations::{AuthSpec, Kind, Registration};

async fn manual(f: &Fixture) -> Registration {
    let r = Registration::new(
        "customer".into(),
        Kind::Tool,
        "manual".into(),
        "https://example.com".into(),
        AuthSpec::None,
    );
    f.repo.create(&r).await.unwrap();
    r
}
#[tokio::test]
async fn stale_credential_writer_cannot_leave_custody_after_pinned_replacement() {
    let f = Fixture::new().await;
    let stale = manual(&f).await;
    f.repo.delete("customer").await.unwrap();
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let before = f.repo.get("customer").await.unwrap();
    assert!(matches!(
        f.repo.store_credential(&stale, &[1; 16], &[2; 12]).await,
        Err(agent_locksmith::registrations::RegistrationError::DefinitionPending)
    ));
    assert_eq!(before, f.repo.get("customer").await.unwrap());
    assert_eq!(super::storage::count(&f, "credential_secrets").await, 0);
}
#[tokio::test]
async fn attachment_failure_rolls_back_sealed_insert() {
    let f = Fixture::new().await;
    let r = manual(&f).await;
    sqlx::query("CREATE TRIGGER fail_attach BEFORE UPDATE ON registrations BEGIN SELECT RAISE(ABORT, 'fixture'); END").execute(&f.pool).await.unwrap();
    assert!(
        f.repo
            .store_credential(&r, &[1; 16], &[2; 12])
            .await
            .is_err()
    );
    assert_eq!(super::storage::count(&f, "credential_secrets").await, 0);
    assert_eq!(r, f.repo.get("customer").await.unwrap().unwrap());
}
