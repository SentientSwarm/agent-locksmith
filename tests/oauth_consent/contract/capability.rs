use super::*;

pub async fn run() {
    let (mut f, t) = journey::ready(false, true, false).await;
    for (index, (plan, reason)) in cases().iter().enumerate() {
        refused(&f, index, plan, reason).await;
    }
    std::fs::remove_file(f.path().join("token-case.json")).unwrap();
    challenge(&f, false).await;
    challenge(&f, true).await;
    assert_eq!(counts(&f)["tool"], Value::Null);
    no_plaintext(&f);
    f.stop();
    t.stop();
    println!(
        "8 token refusals; original sealed verifier received once per challenge; unexpected success unbound; zero business; joined"
    );
}
fn cases() -> Vec<(Value, String)> {
    let mut cases: Vec<(Value, String)> =
        serde_json::from_str(include_str!("refusal-cases.json")).unwrap();
    cases[6].0 = json!({"raw":" ".repeat(65537)});
    cases
}
async fn refused(f: &Fixture, index: usize, plan: &Value, reason: &str) {
    std::fs::write(f.path().join("token-case.json"), plan.to_string()).unwrap();
    let label = format!("token-{index}");
    let created = setup::connect_contract(f, &label);
    let before = prior(f);
    assert_eq!(slack::setup::authorize(f, &created, false).await, 400);
    failed(f, &created, &label, reason);
    assert_eq!(
        counts(f)["token"].as_u64().unwrap(),
        before["token"].as_u64().unwrap_or(0) + 1
    );
    assert_eq!(counts(f)["identity"], before["identity"]);
}
fn failed(f: &Fixture, created: &Value, label: &str, reason: &str) {
    let poll = f.op(&[
        "oauth",
        "attempt-status",
        "fixture",
        created["attempt_id"].as_str().unwrap(),
    ]);
    assert_eq!(poll["state"], "failed");
    assert_eq!(poll["stage"], "token");
    assert_eq!(poll["safe_reason"], reason);
    assert!(!poll.to_string().contains("canary"));
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", label])["state"],
        "absent"
    );
}
async fn challenge(f: &Fixture, accept: bool) {
    let label = if accept { "unexpected" } else { "negative" };
    if accept {
        std::fs::write(f.path().join("accept-wrong-challenge"), "invented").unwrap();
    }
    let created = setup::connect_contract(f, label);
    let changed = super::challenge::adapt(f, &created, label);
    let before = prior(f);
    let callback = super::challenge::issue(f, &changed).await;
    assert_eq!(
        f.http.get(callback).send().await.unwrap().status().as_u16(),
        if accept { 200 } else { 400 }
    );
    challenge_view(f, &created, label, accept);
    challenge_counts(f, &before, accept);
}
fn challenge_counts(f: &Fixture, before: &Value, accept: bool) {
    let after = counts(f);
    assert_eq!(
        after["token"].as_u64().unwrap(),
        before["token"].as_u64().unwrap() + 1
    );
    assert_eq!(
        after["original_verifier_received"].as_u64().unwrap(),
        before["original_verifier_received"].as_u64().unwrap_or(0) + 1
    );
    assert_eq!(
        after["identity"].as_u64().unwrap_or(0),
        before["identity"].as_u64().unwrap_or(0) + u64::from(accept)
    );
}
fn challenge_view(f: &Fixture, created: &Value, label: &str, accept: bool) {
    let view = f.op(&["oauth", "account-status", "fixture", "--label", label]);
    assert_eq!(
        view["state"],
        if accept {
            "connected_unbound"
        } else {
            "absent"
        }
    );
    if accept {
        assert_eq!(view["verified_subject"]["kind"], "user_workspace");
    } else {
        assert_eq!(
            f.op(&[
                "oauth",
                "attempt-status",
                "fixture",
                created["attempt_id"].as_str().unwrap()
            ])["safe_reason"],
            "token_verifier_refused"
        );
    }
}
fn prior(f: &Fixture) -> Value {
    if f.path().join("counts.json").exists() {
        counts(f)
    } else {
        json!({})
    }
}

fn no_plaintext(f: &Fixture) {
    for name in ["daemon.log", "state.db", "state.db-wal"] {
        if let Ok(bytes) = std::fs::read(f.path().join(name)) {
            for secret in [
                "private-token-canary",
                "invented-client-secret",
                "contract-access-1",
                "contract-refresh-1",
            ] {
                assert!(
                    !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "plaintext in {name}"
                );
            }
        }
    }
}
