use super::fixture::*;
use agent_locksmith::registrations::{AuthSpec, Kind, Registration};

#[tokio::test]
async fn changed_subset_or_later_explicit_edit_cannot_reuse_receipt() {
    let f = Fixture::new().await;
    let mut p = f.preview();
    select(&mut p, f.ids[0]);
    success(&f.apply(&p));
    let mut other = p.clone();
    select(&mut other, f.ids[1]);
    conflict(&f.apply(&other));
    assert_eq!(f.count().await, 2);
    f.bindings
        .set(f.ids[0], "api", &AuthSpec::None)
        .await
        .unwrap();
    conflict(&f.apply(&p));
    assert_eq!(
        f.bindings
            .get(f.ids[0], "api")
            .await
            .unwrap()
            .unwrap()
            .auth_spec,
        AuthSpec::None
    );
}
#[tokio::test]
async fn missing_or_invalid_receipt_and_revision_fail_closed() {
    for sql in [
        "DELETE FROM registrations_meta WHERE key LIKE 'explicit_bindings/v1/plan/%'",
        "UPDATE registrations_meta SET value='PRIVATE_BAD_RECEIPT' WHERE key LIKE 'explicit_bindings/v1/plan/%'",
        "DELETE FROM registrations_meta WHERE key='explicit_bindings/v1/revision'",
        "UPDATE registrations_meta SET value='invalid' WHERE key='explicit_bindings/v1/revision'",
    ] {
        let f = Fixture::new().await;
        let mut p = f.preview();
        select(&mut p, f.ids[0]);
        success(&f.apply(&p));
        f.exec(sql).await;
        conflict(&f.apply(&p));
        assert_eq!(f.count().await, 2);
    }
}
#[tokio::test]
async fn new_registration_never_gets_binding_from_old_plan() {
    let f = Fixture::new().await;
    let mut p = f.preview();
    select(&mut p, f.ids[0]);
    success(&f.apply(&p));
    f.registrations
        .create(&Registration::new(
            "future".into(),
            Kind::Tool,
            "test".into(),
            "http://127.0.0.1:1".into(),
            env_spec(),
        ))
        .await
        .unwrap();
    conflict(&f.apply(&p));
    assert!(f.bindings.get(f.ids[0], "future").await.unwrap().is_none());
    assert_eq!(f.count().await, 2);
}
#[tokio::test]
async fn failed_receipt_insert_rolls_back_already_inserted_bindings() {
    let f = Fixture::new().await;
    let mut p = f.preview();
    select(&mut p, f.ids[0]);
    f.exec("CREATE TRIGGER fail_receipt BEFORE INSERT ON registrations_meta WHEN NEW.key LIKE 'explicit_bindings/v1/plan/%' BEGIN SELECT RAISE(ABORT, 'PRIVATE_RECEIPT_FAILURE'); END").await;
    let output = f.apply(&p);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_RECEIPT_FAILURE"));
    assert_eq!(f.count().await, 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM registrations_meta WHERE key LIKE 'explicit_bindings/%'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
async fn missing_database_is_never_created_by_preview_or_apply() {
    let f = Fixture::new().await;
    let missing = f.dir.path().join("not-created.db");
    let output = offline("preview", &missing).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!missing.exists());
    let plan = f.dir.path().join("missing-db-plan.json");
    std::fs::write(&plan, serde_json::to_vec(&f.preview()).unwrap()).unwrap();
    let output = offline("apply", &missing)
        .arg("--plan")
        .arg(plan)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!missing.exists());
}
