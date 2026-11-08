use super::setup;
use agent_locksmith::registrations::AuthSpec;
use serde_json::json;

async fn pool(h: &super::E2E) -> sqlx::SqlitePool {
    sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(h._dir.path().join("locksmith.db")),
    )
    .await
    .unwrap()
}
async fn set(h: &super::E2E, body: serde_json::Value) -> axum_test::TestResponse {
    h.admin
        .put(&format!(
            "/admin/operator/agents/{}/credentials/shared-api/credential",
            h.agent_public_id
        ))
        .add_header("authorization", &h.op_bearer)
        .json(&body)
        .await
}
#[tokio::test]
async fn explicit_bearer_overrides_header_selection_and_header_registration() {
    let h = setup().await;
    let db = pool(&h).await;
    sqlx::query("UPDATE registrations SET auth_json=? WHERE name='shared-api'")
        .bind(json!({"kind":"header","header":"x-key","env_var":"SYNTHETIC"}).to_string())
        .execute(&db)
        .await
        .unwrap();
    set(&h, json!({"value":"synthetic-value","bearer":true}))
        .await
        .assert_status_ok();
    assert!(matches!(selected(&h).await, AuthSpec::StoredBearer { .. }));
    header_selection(&h).await;
    set(&h, json!({"value":"synthetic-next","bearer":true}))
        .await
        .assert_status_ok();
    assert!(matches!(selected(&h).await, AuthSpec::StoredBearer { .. }));
    set(
        &h,
        json!({"value":"rejected","bearer":true,"header":"x-key"}),
    )
    .await
    .assert_status_bad_request();
    db.close().await;
}
async fn header_selection(h: &super::E2E) {
    h.agent_creds
        .set(
            h.agent_id,
            "shared-api",
            &AuthSpec::Header {
                header: "x-key".into(),
                env_var: "SYNTHETIC".into(),
            },
        )
        .await
        .unwrap();
}
async fn selected(h: &super::E2E) -> AuthSpec {
    h.agent_creds
        .get(h.agent_id, "shared-api")
        .await
        .unwrap()
        .unwrap()
        .auth_spec
}
#[tokio::test]
async fn refused_attachment_rolls_back_new_sealed_row() {
    let h = setup().await;
    let db = pool(&h).await;
    set(&h, json!({"value":"synthetic-original","bearer":true}))
        .await
        .assert_status_ok();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_secrets")
        .fetch_one(&db)
        .await
        .unwrap();
    let auth = selected(&h).await;
    sqlx::query("CREATE TRIGGER fixture_attachment_refusal BEFORE INSERT ON agent_credential_overrides BEGIN SELECT RAISE(ABORT,'fixture_refusal'); END").execute(&db).await.unwrap();
    set(&h, json!({"value":"synthetic-refused","bearer":true}))
        .await
        .assert_status_internal_server_error();
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_secrets")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(auth, selected(&h).await);
    db.close().await;
}
