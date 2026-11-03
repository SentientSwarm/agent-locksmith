use crate::fixture::{Fixture, MISSING, X, env_auth};

async fn guidance(h: &Fixture, a: &crate::fixture::Agent) {
    let generic = h.server.get("/skill").await;
    generic.assert_status_ok();
    assert_eq!(generic.header("cache-control"), "public, max-age=86400");
    assert!(!generic.text().contains(&a.public_id));
    let personal = h
        .server
        .get("/skill")
        .add_header("authorization", &a.bearer)
        .await;
    personal.assert_status_ok();
    assert_eq!(
        personal.header("cache-control"),
        "private, no-cache, no-store"
    );
    assert!(personal.text().contains(&a.public_id));
    assert!(
        personal.text().contains("`api`"),
        "unbound tool remains ACL-eligible"
    );
    for text in [generic.text(), personal.text()] {
        content(&text);
        h.safe_surfaces(&text).await;
    }
}

fn content(text: &str) {
    assert!(
        text.contains("account_binding_missing"),
        "missing-binding diagnosis absent"
    );
    let diagnosis = text
        .find("agent credentials list")
        .expect("safe diagnosis command");
    let repair = text
        .find("agent set-credential")
        .expect("deliberate repair command");
    assert!(diagnosis < repair);
    source_guidance(text);
}

fn source_guidance(text: &str) {
    for required in [
        "not_in_allowlist",
        "in_denylist",
        "ACL eligibility",
        "source health",
        "environment",
        "stored",
        "1Password",
        "OAuth",
        "Never retry",
    ] {
        assert!(text.contains(required), "missing guidance: {required}");
    }
}

#[tokio::test]
async fn unbound_agent_gets_actionable_skill_then_deliberate_repair_and_clear() {
    let h = Fixture::new(false).await;
    let a = h.agent("guidance-unbound").await;
    h.denied(&a, 403, "tool_not_allowed", "account_binding_missing")
        .await;
    guidance(&h, &a).await;
    h.bind(&a, &env_auth(false, X)).await;
    h.allowed(&a, "X").await;
    h.bindings.delete(a.id, "api").await.unwrap();
    h.denied(&a, 403, "tool_not_allowed", "account_binding_missing")
        .await;
}

#[tokio::test]
async fn unavailable_selection_guidance_does_not_use_healthy_registration_alternate() {
    let h = Fixture::new(true).await;
    let a = h.agent("guidance-unavailable").await;
    h.bind(&a, &env_auth(true, MISSING)).await;
    h.denied(
        &a,
        503,
        "credential_unresolved",
        "selected_credential_unavailable",
    )
    .await;
    guidance(&h, &a).await;
    h.bind(&a, &env_auth(true, X)).await;
    h.allowed(&a, "X").await;
}
