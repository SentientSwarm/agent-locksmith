use super::*;

pub async fn run() {
    let (mut f, t) = journey::ready(false, false, false).await;
    std::fs::write(f.path().join("missing-scope"), "missing").unwrap();
    let created = setup::connect_contract(&f, "missing");
    assert_eq!(slack::setup::authorize(&f, &created, false).await, 400);
    assert_eq!(counts(&f)["token"], 1);
    assert_eq!(counts(&f)["identity"], Value::Null);
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "missing"])["state"],
        "absent"
    );
    std::fs::remove_file(f.path().join("missing-scope")).unwrap();
    let created = setup::connect_contract(&f, "reader");
    assert_eq!(slack::setup::authorize(&f, &created, false).await, 200);
    refresh_identity(&f);
    retired(&f);
    assert_eq!(counts(&f)["tool"], Value::Null);
    f.stop();
    t.stop();
    println!(
        "custom missing scope: no identity; wrong refresh identity: pending/no replay; retired client: preclaim refusal; zero business; joined"
    );
}
fn refresh_identity(f: &Fixture) {
    std::fs::write(f.path().join("wrong-identity"), "wrong").unwrap();
    let before = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    let out = process::run(f.command(&[
        "oauth",
        "refresh",
        "fixture",
        "--label",
        "reader",
        "--if-match",
        before["revision"].as_str().unwrap(),
    ]));
    assert!(!out.status.success());
    let after = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    assert_eq!(after["refresh_pending"], true);
    assert_eq!(after["verified_subject"], before["verified_subject"]);
    let counts_before = counts(f);
    let again = process::run(f.command(&[
        "oauth",
        "refresh",
        "fixture",
        "--label",
        "reader",
        "--if-match",
        after["revision"].as_str().unwrap(),
    ]));
    assert!(!again.status.success());
    assert_eq!(counts(f), counts_before);
}
fn retired(f: &Fixture) {
    f.op(&[
        "oauth",
        "client",
        "retire",
        "fixture",
        "--profile",
        "fixture",
        "--client-generation",
        "1",
    ]);
    let before = counts(f);
    let out = retired_connect(f);
    assert!(!out.status.success());
    assert_eq!(counts(f), before);
}

fn retired_connect(f: &Fixture) -> std::process::Output {
    let view = f.op(&["oauth", "account-status", "fixture", "--label", "retired"]);
    process::run(f.command(&[
        "oauth",
        "connect",
        "fixture",
        "--label",
        "retired",
        "--profile",
        "fixture",
        "--client-generation",
        "1",
        "--redirect-profile",
        "loopback",
        "--expected-config-revision",
        &view["config_revision"].to_string(),
        "--scopes",
        "catalog:inspect,records:read",
    ]))
}
