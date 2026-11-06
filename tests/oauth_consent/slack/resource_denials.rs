use super::*;

pub async fn endpoints() {
    for wrong in ["", "/wrong"] {
        let (mut f, t) = resource::ready().await;
        setup::create(&f, &t.url(wrong));
        let before = f.op(&["tool", "get", "fixture"]);
        let output = process::run(f.command(&[
            "tool",
            "activate-definition",
            "fixture",
            "--if-match",
            before["definition_control"]["revision"].as_str().unwrap(),
            "--oauth-profile",
            "fixture",
        ]));
        assert!(!output.status.success());
        assert_eq!(f.op(&["tool", "get", "fixture"]), before);
        assert!(!f.path().join("counts.json").exists());
        f.stop();
        t.stop();
    }
    println!("wrong endpoint promotion unchanged; zero provider traffic");
}

pub async fn echo() {
    for refresh in [false, true] {
        let (mut f, t) = resource::ready().await;
        setup::promote(&f, &t);
        setup::provision(&f);
        if refresh {
            let created = setup::connect_slack(&f, "reader");
            assert_eq!(setup::authorize(&f, &created, false).await, 200);
        }
        std::fs::write(f.path().join("wrong-resource-echo"), "invented").unwrap();
        refused(&f, refresh).await;
        f.stop();
        t.stop();
    }
    println!(
        "wrong code/refresh resource echo refuses publication/use; zero business calls/no retry"
    );
}

async fn refused(f: &Fixture, refresh: bool) {
    if refresh {
        assert!(!process::run(lifecycle::refresh(f)).status.success());
    } else {
        let created = setup::connect_slack(f, "reader");
        assert_eq!(setup::authorize(f, &created, false).await, 400);
    }
    let view = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    assert_eq!(
        view["state"],
        if refresh {
            "reconnect_required"
        } else {
            "absent"
        }
    );
    assert_eq!(
        counts(f)["identity"],
        if refresh { json!(1) } else { Value::Null }
    );
    assert_eq!(counts(f)["tool"], Value::Null);
    let before = counts(f);
    assert!(!process::run(lifecycle::refresh(f)).status.success());
    assert_eq!(counts(f), before, "no fallback/replay after refusal");
}
