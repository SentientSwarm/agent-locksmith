use super::*;

fn status(f: &Fixture) -> Value {
    f.op(&["oauth", "account-status", "fixture", "--label", "reader"])
}
pub(super) fn refresh(f: &Fixture) -> std::process::Command {
    f.command(&[
        "oauth",
        "refresh",
        "fixture",
        "--label",
        "reader",
        "--if-match",
        status(f)["revision"].as_str().unwrap(),
    ])
}
pub(super) async fn connected() -> (Fixture, Twin) {
    let (f, t) = failures::ready().await;
    let created = setup::connect_slack(&f, "reader");
    assert_eq!(setup::authorize(&f, &created, false).await, 200);
    (f, t)
}
async fn restart(f: &mut Fixture) {
    f.start_with_keys(
        process::DAEMON,
        Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="),
        Some(KEY),
    )
    .await;
}

pub async fn optional() {
    for absent in ["omit", "null"] {
        let (mut f, t) = failures::ready().await;
        optional_account(&f, absent).await;
        let before = status(&f);
        assert_eq!(before["refresh_available"], false);
        assert_eq!(before["refresh_unavailable_reason"], "refresh_missing");
        assert!(!process::run(refresh(&f)).status.success());
        assert_eq!(status(&f), before);
        let agent = f.op(&[
            "agent",
            "register",
            "--name",
            "access-only",
            "--allowlist",
            "fixture",
        ]);
        receiving::select(&f, &agent);
        receiving::prepare(&f, &agent).await;
        receiving::use_both(&f, &agent).await;
        assert_eq!(counts(&f)["token"], 1);
        assert_eq!(counts(&f)["tool"], 4);
        f.stop();
        t.stop();
        println!(
            "initial {absent} refresh/expiry: no refresh claim/send, native access-only4 effects"
        );
    }
}

pub async fn refresh_optionality() {
    for mode in ["omit", "null"] {
        let (mut f, t) = connected().await;
        std::fs::write(f.path().join(format!("{mode}-refresh_token")), "invented").unwrap();
        let out = process::run(refresh(&f));
        assert_eq!(out.status.success(), mode == "omit");
        assert_eq!(counts(&f)["refresh"], 1);
        let after = status(&f);
        assert_eq!(after["refresh_pending"], mode == "null");
        f.stop();
        restart(&mut f).await;
        assert_eq!(status(&f), after);
        if mode == "omit" {
            assert!(process::run(refresh(&f)).status.success());
        } else {
            assert!(!process::run(refresh(&f)).status.success());
        }
        assert_eq!(counts(&f)["refresh"], if mode == "omit" { 2 } else { 1 });
        f.stop();
        t.stop();
        println!(
            "refresh {mode}: persistence/uncertainty survives joined restart, no automatic replay"
        );
    }
}

pub async fn cancel_and_crash() {
    cancel_exchange().await;
    crash_refresh().await;
}

async fn cancel_exchange() {
    let (mut f, t) = failures::ready().await;
    failures::fault(&f, "token", "hold", 0);
    let created = setup::connect_slack(&f, "cancelled");
    let callback = pending_callback(&f, &created).await;
    arrived(&f, "token").await;
    f.op(&[
        "oauth",
        "cancel",
        "fixture",
        created["attempt_id"].as_str().unwrap(),
    ]);
    std::fs::write(f.path().join("release-token"), "released").unwrap();
    let _ = callback.await.unwrap();
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "cancelled"])["state"],
        "absent"
    );
    assert_eq!(counts(&f)["identity"], Value::Null);
    f.stop();
    t.stop();
}

async fn crash_refresh() {
    let (mut f, t) = connected().await;
    failures::fault(&f, "refresh", "hold", 0);
    let mut child = process::Guard(
        refresh(&f)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    arrived(&f, "refresh").await;
    let pending = status(&f);
    assert_eq!(pending["refresh_pending"], true);
    let mut daemon = f.daemon.take().unwrap();
    daemon.0.kill().unwrap();
    daemon.0.wait().unwrap();
    std::fs::write(f.path().join("release-refresh"), "released").unwrap();
    assert!(!process::wait(&mut child.0).success());
    restart(&mut f).await;
    assert_eq!(status(&f), pending);
    assert!(!process::run(refresh(&f)).status.success());
    assert_eq!(counts(&f)["refresh"], 1);
    assert_eq!(counts(&f)["identity"], 1);
    f.stop();
    t.stop();
    println!(
        "cancelled exchange and consumed-refresh crash: no late publication/replay; pending persisted, joined"
    );
}

async fn optional_account(f: &Fixture, absent: &str) {
    for field in ["refresh_token", "expires_in"] {
        std::fs::write(f.path().join(format!("{absent}-{field}")), "invented").unwrap();
    }
    let created = setup::connect_slack(f, "reader");
    assert_eq!(setup::authorize(f, &created, false).await, 200);
}

pub(super) async fn pending_callback(
    f: &Fixture,
    created: &Value,
) -> tokio::task::JoinHandle<Result<reqwest::Response, reqwest::Error>> {
    let client = f.http.clone();
    let callback_url = setup::issue(f, created, false).await;
    tokio::spawn(async move {
        client
            .get(callback_url)
            .timeout(Duration::from_secs(45))
            .send()
            .await
    })
}
