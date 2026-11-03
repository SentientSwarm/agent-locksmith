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
    missing_audit(f, a);
    rendered_commands(f, &personal);
    upstream::allowed(f, r, &a.token, "accounts/check", "X").await;
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
    println!(
        "AGENT-180 actual generic/personalized skill, audit diagnosis, rendered CLI repair X and clear denial PASS"
    );
}

fn missing_audit(f: &Fixture, a: &setup::Agent) {
    let audit = f.op(&["audit", "query", "--agent", &a.id, "--limit", "100"]);
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["details"]["reason"] == "account_binding_missing")
    );
}

fn rendered_commands(f: &Fixture, personal: &str) {
    let list = command(personal, "agent credentials list", "");
    assert_eq!(
        f.op(&list.iter().map(String::as_str).collect::<Vec<_>>()),
        serde_json::json!([])
    );
    let bind = command(personal, "agent set-credential", "bearer=SMOKE_X");
    f.op(&bind.iter().map(String::as_str).collect::<Vec<_>>());
}

fn command(skill: &str, prefix: &str, source: &str) -> Vec<String> {
    skill
        .lines()
        .rev()
        .find(|line| line.starts_with(&format!("locksmith {prefix}")))
        .expect("personalized operator command")
        .split_whitespace()
        .skip(1)
        .map(|part| match part {
            "<tool>" => "accounts".into(),
            "'bearer=<ENV_VAR>'" => source.into(),
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
