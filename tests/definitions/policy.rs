use super::fixture::{Fixture, definition, instance};
use serde_json::{Value, json};

async fn current(f: &Fixture) -> Value {
    f.server
        .get("/admin/operator/tools/customer")
        .add_header("authorization", &f.token)
        .await
        .json()
}

async fn change(f: &Fixture, state: &Value, body: Value) -> axum_test::TestResponse {
    f.server
        .put("/admin/operator/tools/customer/definition-activation")
        .add_header("authorization", &f.token)
        .add_header(
            "if-match",
            state["definition_control"]["revision"].as_str().unwrap(),
        )
        .json(&body)
        .await
}

fn enabled() -> Value {
    json!({"enabled":true,"compact":true,"contract_policy":"finite-v2",
        "selected_tools":["one","two","three","four"]})
}

async fn fixture(mechanism: &str) -> Fixture {
    let f = Fixture::new().await;
    let mut d = definition();
    d["auth_profiles"][0]["mechanism"] = json!(mechanism);
    f.import(&d)
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f.create("customer", &instance())
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    f
}

#[tokio::test]
async fn finite_policy_promotion_and_reset_preserve_pin_and_refuse_active_changes() {
    for mechanism in ["none", "bearer"] {
        let f = fixture(mechanism).await;
        let initial = current(&f).await;
        let response = change(&f, &initial, enabled()).await;
        response.assert_status_ok();
        let active: Value = response.json();
        assert_eq!(active["mcp"]["definition"], initial["mcp"]["definition"]);
        assert_eq!(active["mcp"]["contract_policy"], "finite-v2");
        assert_eq!(active["mcp"]["selected_tools"], enabled()["selected_tools"]);
        change(&f, &active, enabled()).await.assert_status_ok();
        let mut other = enabled();
        other["selected_tools"] = json!(["other"]);
        change(&f, &active, other).await.assert_status_conflict();
        change(&f, &initial, enabled())
            .await
            .assert_status_conflict();
        assert_eq!(current(&f).await, active);
        reset(&f, &active, &initial).await;
    }
}

async fn reset(f: &Fixture, active: &Value, initial: &Value) {
    change(f, active, json!({"enabled":false}))
        .await
        .assert_status_ok();
    let disabled = current(f).await;
    assert_eq!(disabled["disabled"], true);
    assert_eq!(disabled["mcp"]["definition"], initial["mcp"]["definition"]);
    assert_eq!(disabled["mcp"]["compact"], true);
    for key in ["contract_policy", "selected_tools", "definition_activation"] {
        assert!(disabled["mcp"].get(key).is_none());
    }
    for table in [
        "agent_credential_overrides",
        "credential_secrets",
        "oauth_sessions",
        "agents",
        "bootstrap_tokens",
        "native_reviews",
        "native_tool_grants",
    ] {
        assert_eq!(super::storage::count(f, table).await, 0, "{table}");
    }
    change(f, &disabled, enabled()).await.assert_status_ok();
}

#[tokio::test]
async fn finite_policy_sql_guard_keeps_pin_and_active_configuration_immutable() {
    let f = fixture("bearer").await;
    let initial = current(&f).await;
    let response = change(&f, &initial, enabled()).await;
    response.assert_status_ok();
    let active: Value = response.json();
    for (key, value) in [
        ("selected_tools", json!(["other"])),
        ("contract_policy", json!("finite-v1")),
        ("compact", json!(false)),
        ("definition", json!({})),
        ("protocol_version", json!("other")),
    ] {
        let mut mcp = active["mcp"].clone();
        mcp[key] = value;
        reject_mcp_update(&f, &mcp).await;
        assert_eq!(current(&f).await, active);
    }
    assert!(
        sqlx::query("UPDATE registrations SET disabled=1 WHERE name='customer'")
            .execute(&f.pool)
            .await
            .is_err()
    );
    change(&f, &active, json!({"enabled":false}))
        .await
        .assert_status_ok();
    invalid_new_policy(&f, &active).await;
}

async fn reject_mcp_update(f: &Fixture, mcp: &Value) {
    assert!(
        sqlx::query("UPDATE registrations SET mcp_json=? WHERE name='customer'")
            .bind(mcp.to_string())
            .execute(&f.pool)
            .await
            .is_err()
    );
}

async fn invalid_new_policy(f: &Fixture, active: &Value) {
    let before = current(f).await;
    for (key, value) in [
        ("contract_policy", Value::Null),
        ("contract_policy", json!("unknown")),
        ("selected_tools", Value::Null),
        ("selected_tools", json!([])),
        ("selected_tools", json!(["x", "x"])),
        ("selected_tools", json!([1])),
        ("selected_tools", json!([""])),
    ] {
        let mut mcp = active["mcp"].clone();
        mcp[key] = value;
        assert!(
            sqlx::query("UPDATE registrations SET mcp_json=?,disabled=0 WHERE name='customer'")
                .bind(mcp.to_string())
                .execute(&f.pool)
                .await
                .is_err()
        );
        assert_eq!(current(f).await, before);
    }
}
