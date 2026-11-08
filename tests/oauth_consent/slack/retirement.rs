use super::*;

fn retire(f: &Fixture) {
    let value = f.op(&[
        "oauth",
        "client",
        "retire",
        "fixture",
        "--profile",
        "fixture",
        "--client-generation",
        "1",
    ]);
    assert_eq!(value["state"], "retired");
}

pub async fn held_exchange() {
    let (mut f, t) = failures::ready().await;
    failures::fault(&f, "token", "hold", 0);
    let created = setup::connect_slack(&f, "retired");
    let callback = lifecycle::pending_callback(&f, &created).await;
    arrived(&f, "token").await;
    retire(&f);
    std::fs::write(f.path().join("release-token"), "release").unwrap();
    assert_eq!(callback.await.unwrap().unwrap().status(), 400);
    assert_eq!(counts(&f)["token"], 1);
    assert_eq!(counts(&f)["identity"], Value::Null);
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "retired"])["state"],
        "absent"
    );
    f.stop();
    t.stop();
}

pub async fn held_refresh() {
    let (mut f, t) = lifecycle::connected().await;
    failures::fault(&f, "refresh", "hold", 0);
    let mut child = process::Guard(
        lifecycle::refresh(&f)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    arrived(&f, "refresh").await;
    retire(&f);
    std::fs::write(f.path().join("release-refresh"), "release").unwrap();
    assert!(!process::wait(&mut child.0).success());
    assert_eq!(counts(&f)["refresh"], 1);
    assert_eq!(
        counts(&f)["identity"],
        1,
        "retired client cannot verify/publish new token"
    );
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "reader"])["state"],
        "reconnect_required"
    );
    assert!(!process::run(lifecycle::refresh(&f)).status.success());
    assert_eq!(counts(&f)["refresh"], 1);
    f.stop();
    t.stop();
}
