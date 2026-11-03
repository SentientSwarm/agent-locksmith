use super::{fixture::*, inventory::add};
use agent_locksmith::registrations::AuthSpec;

#[tokio::test]
async fn source_reference_lifecycle_drift_rejects_all_writes() {
    for sql in [
        "UPDATE credential_secrets SET tombstoned_at=2",
        "UPDATE credential_secrets SET set_at=2",
    ] {
        let f = Fixture::new().await;
        add(
            &f,
            "stored",
            AuthSpec::StoredBearer {
                secret_ref: "cs_test".into(),
            },
        )
        .await;
        f.exec("INSERT INTO credential_secrets VALUES ('cs_test',X'00',X'00',1,NULL)")
            .await;
        let mut p = f.preview();
        select(&mut p, f.ids[0]);
        f.exec(sql).await;
        conflict(&f.apply(&p));
        assert_eq!(f.count().await, 1);
    }
}
#[tokio::test]
async fn preserved_or_skipped_row_cannot_be_selected_by_editing_review() {
    for id_index in [2, 3] {
        let f = Fixture::new().await;
        f.exec("UPDATE agents SET tool_allowlist='[]' WHERE name='unmapped'")
            .await;
        let mut p = f.preview();
        let row = p["entries"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["agent_id"] == f.ids[id_index])
            .unwrap();
        row["selected"] = true.into();
        row["action"] = "propose".into();
        conflict(&f.apply(&p));
        assert_eq!(f.count().await, 1);
    }
}
#[tokio::test]
async fn expiry_after_preview_denies_without_database_edits() {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let f = Fixture::new().await;
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 10;
    sqlx::query("UPDATE agents SET expires_at=? WHERE name='shared-a'")
        .bind(expiry)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut p = f.preview();
    select(&mut p, f.ids[0]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Wait strictly beyond expiry, capped at 11 seconds if wall time moves back.
    let wait = expiry.saturating_sub(now).clamp(0, 10) as u64 + 1;
    tokio::time::sleep(Duration::from_secs(wait)).await;
    let after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    assert!(
        after.as_secs() > expiry as u64,
        "wall clock must be strictly past the recorded expiry before apply"
    );
    conflict(&f.apply(&p));
    assert_eq!(f.count().await, 1);
}
