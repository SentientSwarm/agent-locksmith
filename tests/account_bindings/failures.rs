use crate::fixture::{EMPTY, Fixture, MISSING, X, env_auth};

#[tokio::test]
async fn absent_binding_denies_instead_of_inheriting_template() {
    let h = Fixture::new(false).await;
    let a = h.agent("unbound").await;
    h.denied(&a, 403, "tool_not_allowed", "account_binding_missing")
        .await;
}

#[tokio::test]
async fn selection_store_failure_never_dispatches() {
    let h = Fixture::new(false).await;
    let a = h.agent("selected").await;
    h.bind(&a, &env_auth(false, X)).await;
    h.allowed(&a, "X").await;
    sqlx::query("DROP TABLE agent_credential_overrides")
        .execute(&h.pool)
        .await
        .unwrap();
    h.denied(
        &a,
        503,
        "credential_unresolved",
        "account_binding_unavailable",
    )
    .await;
}

#[tokio::test]
async fn corrupt_selection_is_unavailable_without_disclosing_input() {
    let h = Fixture::new(false).await;
    let a = h.agent("corrupt").await;
    h.bind(&a, &env_auth(false, X)).await;
    sqlx::query("UPDATE agent_credential_overrides SET auth_spec = ?")
        .bind("{\"kind\":\"d1-private-X\"}")
        .execute(&h.pool)
        .await
        .unwrap();
    h.denied(
        &a,
        503,
        "credential_unresolved",
        "account_binding_unavailable",
    )
    .await;
}

async fn unavailable_env(is_header: bool, variable: &str) {
    let h = Fixture::new(is_header).await;
    let a = h.agent("env").await;
    h.bind(&a, &env_auth(is_header, variable)).await;
    h.denied(
        &a,
        503,
        "credential_unresolved",
        "selected_credential_unavailable",
    )
    .await;
}

#[tokio::test]
async fn missing_selected_header_never_uses_cached_template() {
    unavailable_env(true, MISSING).await;
}
#[tokio::test]
async fn missing_selected_bearer_never_uses_cached_template() {
    unavailable_env(false, MISSING).await;
}
#[tokio::test]
async fn empty_selected_header_never_dispatches() {
    unavailable_env(true, EMPTY).await;
}
#[tokio::test]
async fn empty_selected_bearer_never_dispatches() {
    unavailable_env(false, EMPTY).await;
}

#[tokio::test]
async fn acl_denial_precedes_broken_selection_store() {
    let h = Fixture::new(false).await;
    let a = h.agent("denied").await;
    h.agents
        .update_policy(&a.public_id, Some(Some(vec![])), None, None, None)
        .await
        .unwrap();
    sqlx::query("DROP TABLE agent_credential_overrides")
        .execute(&h.pool)
        .await
        .unwrap();
    h.denied(&a, 403, "tool_not_allowed", "not_in_allowlist")
        .await;
}

#[tokio::test]
async fn revoked_or_invalid_identity_never_reaches_selection_or_upstream() {
    let h = Fixture::new(false).await;
    let a = h.agent("revoked").await;
    h.bind(&a, &env_auth(false, X)).await;
    h.allowed(&a, "X").await;
    h.agents.revoke(&a.public_id).await.unwrap();
    sqlx::query("DROP TABLE agent_credential_overrides")
        .execute(&h.pool)
        .await
        .unwrap();
    let before = h.count().await;
    let responses = [
        // Revoked agents are hidden by the active-agent lookup.
        (h.call(&a).await, "invalid_credential"),
        (h.server.get("/api/api/check").await, "invalid_credential"),
        (
            h.server
                .get("/api/api/check")
                .add_header("authorization", "Bearer lk_bad.invalid")
                .await,
            "invalid_credential",
        ),
    ];
    for (response, code) in responses {
        response.assert_status_unauthorized();
        assert_eq!(response.json::<serde_json::Value>()["error"]["code"], code);
        h.safe_surfaces(&response.text()).await;
    }
    assert_eq!(h.count().await, before);
}

#[tokio::test]
async fn public_template_without_explicit_none_is_denied() {
    let h = Fixture::new(false).await;
    let a = h.agent("unbound-public").await;
    sqlx::query("UPDATE registrations SET auth_json = ? WHERE name = 'api'")
        .bind(r#"{"kind":"none"}"#)
        .execute(&h.pool)
        .await
        .unwrap();
    h.catalog.store(std::sync::Arc::new(
        agent_locksmith::registrations::Catalog::from_repo(&h.registrations)
            .await
            .unwrap(),
    ));
    h.denied(&a, 403, "tool_not_allowed", "account_binding_missing")
        .await;
}

#[tokio::test]
async fn unwired_selection_repository_is_unavailable() {
    let mut h = Fixture::new(false).await;
    let a = h.agent("unwired").await;
    h.bind(&a, &env_auth(false, X)).await;
    h.server = crate::application::server(
        &h.agents,
        None,
        &h.registrations,
        h.catalog.clone(),
        h.audit.clone(),
    );
    h.denied(
        &a,
        503,
        "credential_unresolved",
        "account_binding_unavailable",
    )
    .await;
}
