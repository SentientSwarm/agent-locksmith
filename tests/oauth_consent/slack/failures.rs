use super::*;

pub(super) async fn ready() -> (Fixture, Twin) {
    let (f, t) = unprovisioned().await;
    setup::provision(&f);
    (f, t)
}

pub(super) async fn unprovisioned() -> (Fixture, Twin) {
    let mut f = Fixture::new();
    let t = Twin::script(
        &f,
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/oauth_consent/slack/provider.py"
        ),
    );
    setup::configure_slack(&f, &t);
    f.start_with_keys(
        process::DAEMON,
        Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="),
        Some(KEY),
    )
    .await;
    setup::promote(&f, &t);
    (f, t)
}

pub(super) fn fault(f: &Fixture, phase: &str, mode: &str, seconds: u64) {
    std::fs::write(
        f.path().join("fault.json"),
        json!({"phase":phase,"mode":mode,"seconds":seconds}).to_string(),
    )
    .unwrap();
}

pub async fn token_http() {
    let (mut f, t) = ready().await;
    fault(&f, "token", "abort", 0);
    refused(&f, "http").await;
    assert_eq!(counts(&f)["token"], 1);
    assert_eq!(counts(&f)["identity"], Value::Null);
    f.stop();
    t.stop();
}

async fn refused(f: &Fixture, reason: &str) {
    let created = setup::connect_slack(f, "refused");
    assert_eq!(setup::authorize(f, &created, false).await, 400);
    let state = f.op(&[
        "oauth",
        "attempt-status",
        "fixture",
        created["attempt_id"].as_str().unwrap(),
    ]);
    assert_eq!(state["safe_reason"], reason);
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "refused"])["state"],
        "absent"
    );
}

pub async fn deadlines() {
    for (phase, mode, seconds) in [
        ("token", "headers", 31),
        ("token", "body", 31),
        ("identity", "headers", 6),
        ("identity", "body", 6),
    ] {
        let (mut f, t) = ready().await;
        fault(&f, phase, mode, seconds);
        let start = Instant::now();
        refused(&f, "deadline").await;
        assert!(start.elapsed() >= Duration::from_secs(if phase == "token" { 29 } else { 4 }));
        assert_eq!(counts(&f)["token"], 1, "no retry");
        f.stop();
        t.stop();
        println!("Slack {phase}/{mode} actual deadline; absent account; joined");
    }
}

pub async fn native_deadlines() {
    for mode in ["headers", "body", "sse"] {
        let (mut f, t) = ready().await;
        let created = setup::connect_slack(&f, "reader");
        assert_eq!(setup::authorize(&f, &created, false).await, 200);
        let agent = f.op(&[
            "agent",
            "register",
            "--name",
            "delay",
            "--allowlist",
            "fixture",
        ]);
        receiving::select(&f, &agent);
        fault(&f, "native-initialize", mode, 11);
        observe_refused(&f, &agent).await;
        assert_eq!(counts(&f)["native-initialize"], 1);
        assert_eq!(counts(&f)["tool"], Value::Null);
        f.stop();
        t.stop();
        println!("Native {mode} actual 10s deadline; zero calls; joined");
    }
}

async fn observe_refused(f: &Fixture, agent: &Value) {
    let path = format!(
        "/admin/operator/tools/fixture/mcp/observations/{}",
        agent["public_id"].as_str().unwrap()
    );
    let (status, before) = request(f, "GET", &path, None).await;
    assert_eq!(status, 200);
    let start = Instant::now();
    let (status, result) = request(
        f,
        "POST",
        &path,
        Some(json!({"source":before["source"],"generation":before["observation"]["generation"]})),
    )
    .await;
    assert_eq!(status, 408, "{result}");
    assert_eq!(result["error"]["code"], "operation_deadline", "{result}");
    assert!(start.elapsed() >= Duration::from_secs(9));
}
