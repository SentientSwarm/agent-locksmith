use super::fixture::{Fixture, definition, instance};
use agent_locksmith::definitions::parse;
use serde_json::{Value, json};

#[tokio::test]
async fn repeated_content_is_noop_and_conflicting_revision_is_atomic() {
    let f = Fixture::new().await;
    let d = definition();
    f.import(&d)
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let before = saved(&f).await;
    f.import(&d).await.assert_status_ok();
    let mut conflict = d.clone();
    conflict["summary"] = json!("changed");
    f.import(&conflict).await.assert_status_conflict();
    let after = saved(&f).await;
    assert_eq!(before, after);
    assert!(
        sqlx::query("UPDATE integration_definitions SET created_at = 0")
            .execute(&f.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM integration_definitions")
            .execute(&f.pool)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn concurrent_immutable_collision_has_one_winner() {
    let f = Fixture::new().await;
    let mut other = definition();
    other["summary"] = json!("other");
    let a = parse(definition().to_string().as_bytes()).unwrap();
    let b = parse(other.to_string().as_bytes()).unwrap();
    let (a, b) = tokio::join!(f.repo.import_definition(&a), f.repo.import_definition(&b));
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(count(&f, "integration_definitions").await, 1);
}
#[tokio::test]
async fn exact_pin_survives_new_revision_and_collisions() {
    let f = Fixture::new().await;
    let mut d = definition();
    f.import(&d)
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let old: Value = f.create("customer", &instance()).await.json();
    d["revision"] = json!(2);
    d["summary"] = json!("revised");
    f.import(&d)
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let before = f.repo.get("customer").await.unwrap().unwrap();
    let mut input = instance();
    input["definition"]["revision"] = json!(2);
    f.create("customer", &input).await.assert_status_conflict();
    let new: Value = f.create("customer-two", &input).await.json();
    assert_ne!(
        old["mcp"]["definition"]["digest"],
        new["mcp"]["definition"]["digest"]
    );
    assert_eq!(f.repo.get("customer").await.unwrap().unwrap(), before);
    input["definition"]["revision"] = json!(3);
    f.create("missing", &input).await.assert_status_not_found();
    input = instance();
    input["auth_profile_id"] = json!("missing");
    f.create("bad", &input).await.assert_status_bad_request();
    assert_eq!(count(&f, "registrations").await, 2);
}
#[tokio::test]
async fn import_and_create_grant_no_authority_or_custody() {
    let f = Fixture::new().await;
    f.server
        .put("/admin/operator/integration-definitions/local.customer/revisions/1")
        .json(&definition())
        .await
        .assert_status_unauthorized();
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    for table in [
        "agents",
        "bootstrap_tokens",
        "agent_credential_overrides",
        "credential_secrets",
        "oauth_sessions",
    ] {
        assert_eq!(count(&f, table).await, 0, "{table}");
    }
}
pub async fn count(f: &Fixture, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(&f.pool)
        .await
        .unwrap()
}

async fn saved(f: &Fixture) -> (String, String, i64) {
    sqlx::query_as("SELECT canonical_json,digest,created_at FROM integration_definitions")
        .fetch_one(&f.pool)
        .await
        .unwrap()
}
