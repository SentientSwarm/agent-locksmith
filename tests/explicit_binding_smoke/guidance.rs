use super::{
    fixture::Fixture,
    safety, setup,
    upstream::{self, Receiver},
};

pub async fn repair(f: &Fixture, r: &Receiver, a: &setup::Agent) {
    let generic = fetch(f, None).await;
    assert!(!generic.contains(&a.id));
    let personal = fetch(f, Some(&a.token)).await;
    assert!(personal.contains("`accounts`"));
    let before = policy(f, &a.id);
    audit(f, &personal, "reason", "account_binding_missing");
    assert_eq!(
        run_rendered(f, &personal, "agent credentials list", ""),
        serde_json::json!([])
    );
    run_rendered(f, &personal, "agent set-credential", "bearer=SMOKE_X");
    assert_eq!(policy(f, &a.id), before);
    upstream::allowed(f, r, &a.token, "accounts/check", "X").await;
    clear_denies(f, r, a).await;
    repair_source(f, r, a).await;
    println!(
        "AGENT-65 actual skill audit/list/set commands repair missing binding and unavailable source to X without changing grants; clear denies again"
    );
}

async fn clear_denies(f: &Fixture, r: &Receiver, a: &setup::Agent) {
    setup::clear(f, a);
    upstream::denied(
        f,
        r,
        Some(&a.token),
        "accounts/check",
        403,
        "tool_not_allowed",
    )
    .await;
}

async fn repair_source(f: &Fixture, r: &Receiver, a: &setup::Agent) {
    setup::bind(f, a, "bearer=SMOKE_MISSING");
    upstream::denied(
        f,
        r,
        Some(&a.token),
        "accounts/check",
        503,
        "credential_unresolved",
    )
    .await;
    let before = policy(f, &a.id);
    let personal = fetch(f, Some(&a.token)).await;
    audit(
        f,
        &personal,
        "credential_cause",
        "selected_credential_unavailable",
    );
    let selected = run_rendered(f, &personal, "agent credentials list", "");
    assert!(selected.to_string().contains("SMOKE_MISSING"));
    run_rendered(f, &personal, "agent set-credential", "bearer=SMOKE_X");
    assert_eq!(policy(f, &a.id), before);
    upstream::allowed(f, r, &a.token, "accounts/check", "X").await;
    clear_denies(f, r, a).await;
}

fn policy(f: &Fixture, agent: &str) -> serde_json::Value {
    let mut row = f.op(&["agent", "get", agent]);
    // Authenticated discovery legitimately advances usage, not policy.
    row.as_object_mut().unwrap().remove("last_used_at");
    row
}

fn audit(f: &Fixture, personal: &str, field: &str, reason: &str) {
    let audit = run_rendered(f, personal, "audit query", "");
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["details"][field] == reason),
        "rendered audit query omitted {field}={reason}"
    );
}

fn run_rendered(f: &Fixture, personal: &str, prefix: &str, source: &str) -> serde_json::Value {
    let args = command(personal, prefix, source);
    f.op(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

fn command(skill: &str, prefix: &str, source: &str) -> Vec<String> {
    skill
        .replace("\\\n", "")
        .lines()
        .rev()
        .find(|line| line.starts_with(&format!("locksmith {prefix}")))
        .expect("personalized operator command")
        .split_whitespace()
        .skip(1)
        .map(|part| match part {
            "<tool>" => "accounts".into(),
            "'bearer=<ENV_VAR>'" => source.into(),
            "<ms>" => "0".into(),
            other => other.into(),
        })
        .collect()
}

async fn fetch(f: &Fixture, token: Option<&str>) -> String {
    let mut request = f.http.get(f.url("/skill"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["cache-control"],
        if token.is_some() {
            "private, no-cache, no-store"
        } else {
            "public, max-age=86400"
        }
    );
    let text = response.text().await.unwrap();
    content(&text);
    let tokens = f.tokens.borrow();
    safety::no_values(
        &text,
        &tokens.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    text
}

fn content(text: &str) {
    for required in [
        "account_binding_missing",
        "not_in_allowlist",
        "in_denylist",
        "agent credentials list",
        "agent set-credential",
        "ACL eligibility",
        "source health",
        "environment",
        "stored",
        "1Password",
        "OAuth",
        "Never retry",
    ] {
        assert!(
            text.contains(required),
            "missing shipped guidance: {required}"
        );
    }
}
