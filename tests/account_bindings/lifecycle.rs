use crate::fixture::{Fixture, X, Y, env_auth};
use agent_locksmith::registrations::{AuthSpec, Catalog};
use std::sync::Arc;

async fn explicit_accounts(is_header: bool) {
    let h = Fixture::new(is_header).await;
    let a = h.agent("shared-a").await;
    let b = h.agent("shared-b").await;
    let c = h.agent("distinct-c").await;
    for agent in [&a, &b] {
        h.bind(agent, &env_auth(is_header, X)).await;
    }
    h.bind(&c, &env_auth(is_header, Y)).await;
    h.allowed(&a, "X").await;
    h.allowed(&b, "X").await;
    h.allowed(&c, "Y").await;
}

#[tokio::test]
async fn explicit_bearer_accounts_are_shared_x_x_and_distinct_y() {
    explicit_accounts(false).await;
}
#[tokio::test]
async fn explicit_header_accounts_are_shared_x_x_and_distinct_y() {
    explicit_accounts(true).await;
}

#[tokio::test]
async fn explicit_none_strips_caller_auth_and_remains_subject_to_acl() {
    let h = Fixture::new(false).await;
    let a = h.agent("public").await;
    h.bind(&a, &AuthSpec::None).await;
    h.allowed(&a, "UNAPPROVED").await;
    let requests = h.mock.received_requests().await.unwrap();
    assert!(requests[0].headers.get("authorization").is_none());
    assert!(requests[0].headers.get("x-api-key").is_none());
    h.agents
        .update_policy(&a.public_id, Some(Some(vec![])), None, None, None)
        .await
        .unwrap();
    h.denied(&a, 403, "tool_not_allowed", "not_in_allowlist")
        .await;
}

#[tokio::test]
async fn clear_denies_next_admission() {
    let h = Fixture::new(false).await;
    let a = h.agent("changes").await;
    h.bind(&a, &env_auth(false, X)).await;
    h.allowed(&a, "X").await;
    h.bindings.delete(a.id, "api").await.unwrap();
    h.denied(&a, 403, "tool_not_allowed", "account_binding_missing")
        .await;
}

#[tokio::test]
async fn replacement_affects_next_admission() {
    let h = Fixture::new(false).await;
    let a = h.agent("replacement").await;
    h.bind(&a, &env_auth(false, X)).await;
    h.allowed(&a, "X").await;
    h.bind(&a, &env_auth(false, Y)).await;
    h.allowed(&a, "Y").await;
}

#[tokio::test]
async fn template_change_neither_repoints_selection_nor_admits_unbound_agent() {
    let h = Fixture::new(false).await;
    let a = h.agent("selected").await;
    let b = h.agent("unbound").await;
    h.bind(&a, &env_auth(false, X)).await;
    h.allowed(&a, "X").await;
    sqlx::query("UPDATE registrations SET auth_json = ? WHERE name = 'api'")
        .bind(serde_json::to_string(&env_auth(false, Y)).unwrap())
        .execute(&h.pool)
        .await
        .unwrap();
    h.catalog.store(Arc::new(
        Catalog::from_repo(&h.registrations).await.unwrap(),
    ));
    h.allowed(&a, "X").await;
    h.denied(&b, 403, "tool_not_allowed", "account_binding_missing")
        .await;
}
