use super::{callback_support::*, *};

const DEDICATED: &str = "/oauth/callback/slack";

pub async fn positive() {
    let (mut f, t) = ready(true).await;
    for (label, omit) in [("absent", true), ("exact", false)] {
        accepted(&f, label, omit).await;
    }
    let wrong = setup::connect_slack(&f, "wrong-verifier");
    let raw = setup::issue(&f, &wrong, true).await;
    assert_eq!(send(&f, without_issuer(&raw)).await, 400);
    assert_eq!(
        counts(&f),
        json!({"issued_code":3,"token":3,"identity":2,"matched_verifier":2,"bad_verifier":1})
    );
    f.stop();
    t.stop();
}

pub async fn adversarial() {
    let (mut f, t) = ready(true).await;
    let attempt = setup::connect_slack(&f, "adverse");
    let raw = setup::issue(&f, &attempt, false).await;
    let base = without_issuer(&raw);
    variants(&f, &attempt, &base).await;
    headers(&f, &attempt, &base).await;
    unknown_state(&f, &attempt, &base).await;
    assert_eq!(
        send(&f, base).await,
        200,
        "refusals preserve valid callback"
    );
    assert_eq!(counts(&f)["token"], 1);
    assert_eq!(counts(&f)["identity"], 1);
    f.stop();
    t.stop();
}

pub async fn legacy() {
    let (mut f, t) = ready(false).await;
    let attempt = setup::connect_slack(&f, "legacy");
    let raw = setup::issue(&f, &attempt, false).await;
    let mut url = without_issuer(&raw);
    refused(&f, &attempt, url.clone()).await;
    url.set_path(DEDICATED);
    refused(&f, &attempt, url).await;
    assert_eq!(send(&f, raw.parse().unwrap()).await, 200);
    assert_eq!(counts(&f)["token"], 1);
    assert_eq!(counts(&f)["identity"], 1);
    f.stop();
    t.stop();
}

async fn accepted(f: &Fixture, label: &str, omit: bool) {
    let attempt = setup::connect_slack(f, label);
    let raw = setup::issue(f, &attempt, false).await;
    let url = if omit {
        without_issuer(&raw)
    } else {
        raw.parse().unwrap()
    };
    assert_eq!(url.path(), DEDICATED);
    assert_eq!(send(f, url.clone()).await, 200);
    assert_eq!(send(f, url).await, 400, "state is one-use");
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", label])["state"],
        "connected_unbound"
    );
}

async fn variants(f: &Fixture, attempt: &Value, base: &reqwest::Url) {
    for suffix in [
        "&iss=",
        "&iss=https%3A%2F%2Fwrong.test",
        "&iss=%GG",
        "&iss=%FF",
        "&iss=a&%69ss=b",
    ] {
        refused(f, attempt, format!("{base}{suffix}").parse().unwrap()).await;
    }
    for path in [
        "/oauth/callback",
        "/oauth/callback/%73lack",
        "/oauth/callback/slack/",
    ] {
        let mut changed = base.clone();
        changed.set_path(path);
        refused(f, attempt, changed).await;
    }
}
