use super::fixture::{Fixture, definition, instance};
use serde_json::json;

#[tokio::test]
async fn legacy_operator_writers_cannot_edit_or_enable_pins() {
    let f = Fixture::new().await;
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let before = f.repo.get("customer").await.unwrap().unwrap();
    f.server
        .put("/admin/operator/tools/customer")
        .add_header("authorization", &f.token)
        .json(&json!({"upstream":"https://example.com/other","auth":{"kind":"none"}}))
        .await
        .assert_status_conflict();
    f.server
        .post("/admin/operator/tools/customer/enable")
        .add_header("authorization", &f.token)
        .await
        .assert_status_conflict();
    credential_refusals(&f).await;
    assert_eq!(before, f.repo.get("customer").await.unwrap().unwrap());
    assert_eq!(super::storage::count(&f, "credential_secrets").await, 0);
}
#[tokio::test]
async fn repository_and_sql_cannot_strip_change_enable_or_forge_pin() {
    let f = Fixture::new().await;
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let before = f.repo.get("customer").await.unwrap().unwrap();
    let mut stripped = before.clone();
    stripped.mcp.as_mut().unwrap().definition = None;
    assert!(f.repo.upsert(&stripped).await.is_err());
    let mut retained = before.clone();
    retained.description = "changed".into();
    assert!(f.repo.upsert(&retained).await.is_err());
    assert!(f.repo.set_disabled("customer", false).await.is_err());
    malformed_pins(&f).await;
    assert_eq!(before, f.repo.get("customer").await.unwrap().unwrap());
    assert_eq!(super::storage::count(&f, "registrations").await, 1);
}
#[tokio::test]
async fn seed_pin_is_rejected_before_any_entry_or_version_change() {
    let f = Fixture::new().await;
    f.import(&definition())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let entry = json!({"name":"forged","kind":"tool","protocol":"mcp_streamable_http","upstream":"https://example.com","auth":{"kind":"none"},"egress":"direct","mcp":{"protocol_version":"2025-11-25","definition":{"id":"local.customer","revision":1,"digest":"bad","auth_profile_id":"none"}}});
    let earlier = json!({"name":"early","kind":"tool","upstream":"https://example.com","auth":{"kind":"none"}});
    let seed = json!({"version":"99.0.0","entries":[earlier,entry]});
    assert!(
        agent_locksmith::registrations::seed_loader::apply_catalog(&f.repo, &seed.to_string())
            .await
            .is_err()
    );
    assert_eq!(super::storage::count(&f, "registrations").await, 0);
    assert!(f.repo.get_seed_version().await.unwrap().is_none());
}

async fn credential_refusals(f: &Fixture) {
    for method in ["PUT", "DELETE"] {
        let url = "/admin/operator/tools/customer/credential";
        let req = if method == "PUT" {
            f.server
                .put(url)
                .json(&json!({"value":"synthetic-definition-canary"}))
        } else {
            f.server.delete(url)
        };
        req.add_header("authorization", &f.token)
            .await
            .assert_status_conflict();
    }
}

async fn malformed_pins(f: &Fixture) {
    for pin in [
        json!(null),
        json!({}),
        json!({"id":"local.customer","revision":1,"digest":null,"auth_profile_id":"none"}),
    ] {
        let mcp = json!({"protocol_version":"2025-11-25","allow_private_destination":false,"definition":pin});
        let query = "INSERT INTO registrations SELECT 'forged',kind,description,upstream,auth_json,egress,timeouts_json,body_limit_bytes,metadata_json,seed,disabled,created_at,updated_at,protocol,? FROM registrations WHERE name='customer'";
        assert!(
            sqlx::query(query)
                .bind(mcp.to_string())
                .execute(&f.pool)
                .await
                .is_err()
        );
    }
}
