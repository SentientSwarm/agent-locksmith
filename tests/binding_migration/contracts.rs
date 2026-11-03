use super::fixture::*;

#[tokio::test]
async fn preview_is_deterministic_read_only_and_never_exports_values() {
    let f = Fixture::new().await;
    f.exec("PRAGMA wal_checkpoint(TRUNCATE)").await;
    let before = std::fs::read(&f.db).unwrap();
    let first = f.preview();
    assert_eq!(first, f.preview());
    assert_eq!(before, std::fs::read(&f.db).unwrap());
    assert_eq!(f.count().await, 1);
    let text = first.to_string();
    assert!(text.contains("MIGRATION_X"));
    for private in [
        "PRIVATE_ENV_SENTINEL",
        "PRIVATE_OPERATOR_SENTINEL",
        "secret_hash",
        "ciphertext",
        "sealed_value",
    ] {
        assert!(!text.contains(private), "leaked {private}");
    }
    assert_eq!(first["entries"][2]["action"], "preserve");
}

#[tokio::test]
async fn selected_subset_repeats_but_later_clear_or_missing_receipt_cannot_recreate() {
    let f = Fixture::new().await;
    let mut p = f.preview();
    select(&mut p, f.ids[0]);
    success(&f.apply(&p));
    assert_eq!(f.count().await, 2);
    success(&f.apply(&p));
    f.bindings.delete(f.ids[0], "api").await.unwrap();
    conflict(&f.apply(&p));
    assert_eq!(f.count().await, 1);
    f.exec("DELETE FROM registrations_meta WHERE key LIKE 'explicit_bindings/v1/plan/%'")
        .await;
    conflict(&f.apply(&p));
    assert_eq!(f.count().await, 1);
    let keep: String =
        sqlx::query_scalar("SELECT value FROM registrations_meta WHERE key='seed_version'")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(keep, "keep");
    let unrelated: String =
        sqlx::query_scalar("SELECT value FROM registrations_meta WHERE key='unrelated'")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(unrelated, "keep-too");
}

#[tokio::test]
async fn relevant_drift_or_edited_mapping_rejects_without_partial_bindings() {
    for sql in [
        "UPDATE registrations SET upstream='http://changed:1'",
        "UPDATE agents SET revoked_at=1 WHERE name='shared-a'",
        "UPDATE agents SET tool_denylist='[\"api\"]' WHERE name='shared-b'",
        "UPDATE agent_credential_overrides SET auth_spec='{\"kind\":\"none\"}'",
    ] {
        let f = Fixture::new().await;
        let mut p = f.preview();
        select(&mut p, f.ids[0]);
        f.exec(sql).await;
        conflict(&f.apply(&p));
        assert_eq!(f.count().await, 1, "{sql}");
    }
    let f = Fixture::new().await;
    let mut p = f.preview();
    select(&mut p, f.ids[0]);
    p["entries"][0]["auth_spec"]["env_var"] = "UNREVIEWED".into();
    conflict(&f.apply(&p));
    assert_eq!(f.count().await, 1);
}

#[tokio::test]
async fn midway_sql_failure_rolls_back_both_bindings_and_receipt() {
    let f = Fixture::new().await;
    let mut p = f.preview();
    select(&mut p, f.ids[0]);
    select(&mut p, f.ids[1]);
    f.exec("CREATE TRIGGER fail_second BEFORE INSERT ON agent_credential_overrides WHEN NEW.agent_id=2 BEGIN SELECT RAISE(ABORT, 'PRIVATE_TRIGGER_SENTINEL'); END").await;
    let output = f.apply(&p);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_TRIGGER_SENTINEL"));
    assert_eq!(f.count().await, 1);
    let receipts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM registrations_meta WHERE key LIKE 'explicit_bindings/%'",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(receipts, 0);
}
