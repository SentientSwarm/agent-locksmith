use super::*;

pub(super) async fn ready(dedicated: bool) -> (Fixture, Twin) {
    let mut f = Fixture::new();
    let t = Twin::script(
        &f,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/oauth_consent/slack/provider.py"
        ),
    );
    setup::configure_slack(&f, &t);
    configure_route(&f, dedicated);
    f.start_with_keys(
        process::DAEMON,
        Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="),
        Some(KEY),
    )
    .await;
    setup::promote(&f, &t);
    setup::provision(&f);
    (f, t)
}

pub(super) fn without_issuer(raw: &str) -> reqwest::Url {
    let mut url = reqwest::Url::parse(raw).unwrap();
    let pairs: Vec<_> = url
        .query_pairs()
        .into_owned()
        .filter(|(k, _)| k != "iss")
        .collect();
    url.set_query(None);
    url.query_pairs_mut().extend_pairs(pairs);
    url
}

pub(super) async fn send(f: &Fixture, url: reqwest::Url) -> u16 {
    f.http.get(url).send().await.unwrap().status().as_u16()
}

pub(super) fn pending(f: &Fixture, attempt: &Value) -> Value {
    let status = f.op(&[
        "oauth",
        "attempt-status",
        "fixture",
        attempt["attempt_id"].as_str().unwrap(),
    ]);
    assert_eq!(status["state"], "pending");
    assert_eq!(status["stage"], "created");
    status
}

pub(super) async fn refused(f: &Fixture, attempt: &Value, url: reqwest::Url) {
    let before = pending(f, attempt);
    let arrivals = counts(f);
    assert_eq!(send(f, url).await, 400);
    assert_eq!(
        pending(f, attempt),
        before,
        "refusal must not consume state"
    );
    assert_eq!(counts(f), arrivals, "zero token/identity arrivals");
}

fn configure_route(f: &Fixture, dedicated: bool) {
    if dedicated {
        let path = f.path().join("config.yaml");
        let mut c: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let p = &mut c["oauth_consent"]["profiles"][0];
        p["redirect_uri"] = json!(format!("{}/slack", p["redirect_uri"].as_str().unwrap()));
        std::fs::write(path, c.to_string()).unwrap();
    }
}
pub(super) async fn headers(f: &Fixture, attempt: &Value, base: &reqwest::Url) {
    let before = pending(f, attempt);
    let arrivals = counts(f);
    for (key, value) in [
        ("host", "wrong.test"),
        ("forwarded", "host=wrong.test"),
        ("x-forwarded-host", "wrong.test"),
    ] {
        assert_eq!(
            f.http
                .get(base.clone())
                .header(key, value)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
        assert_eq!(pending(f, attempt), before);
        assert_eq!(counts(f), arrivals);
    }
}

pub(super) async fn unknown_state(f: &Fixture, attempt: &Value, base: &reqwest::Url) {
    let mut changed = base.clone();
    let pairs: Vec<_> = changed
        .query_pairs()
        .into_owned()
        .filter(|(k, _)| k != "state")
        .collect();
    changed.set_query(None);
    changed
        .query_pairs_mut()
        .extend_pairs(pairs)
        .append_pair("state", &"x".repeat(43));
    refused(f, attempt, changed).await;
}
