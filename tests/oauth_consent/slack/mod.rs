use super::*;
pub mod callback;
pub mod callback_custody;
mod callback_support;
pub mod clients;
mod denials;
pub mod dispatch;
pub mod failures;
pub mod lifecycle;
pub mod metadata;
pub mod metadata_refresh;
mod receiving;
mod reconnect;
pub mod resource;
pub mod resource_denials;
pub mod retirement;
mod setup;

pub async fn journey() {
    let (mut f, twin) = failures::ready().await;
    exchanges(&f).await;
    let agent = f.op(&[
        "agent",
        "register",
        "--name",
        "slack-reader",
        "--allowlist",
        "fixture",
    ]);
    receiving::select(&f, &agent);
    denials::denied_tools(&f, &agent).await;
    receiving::prepare(&f, &agent).await;
    receiving::use_both(&f, &agent).await;
    assert_eq!(counts(&f)["tool"], 4);
    refresh_restart(&mut f, &agent).await;
    reconnect::run(&f, &agent).await;
    retire(&f);
    f.stop();
    twin.stop();
    println!(
        "Slack confidential: positive/refused verifier, both facades4+4+4, refresh/restart/reconnect, retirement; joined"
    );
}

async fn exchanges(f: &Fixture) {
    let positive = setup::connect_slack(f, "reader");
    assert_eq!(setup::authorize(f, &positive, false).await, 200);
    let negative = setup::connect_slack(f, "wrong");
    assert_eq!(setup::authorize(f, &negative, true).await, 400);
    assert_eq!(
        counts(f),
        json!({"issued_code":2,"token":2,"identity":1,"matched_verifier":1,"bad_verifier":1})
    );
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "wrong"])["state"],
        "absent"
    );
}

async fn refresh_restart(f: &mut Fixture, agent: &Value) {
    let account = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    f.op(&[
        "oauth",
        "refresh",
        "fixture",
        "--label",
        "reader",
        "--if-match",
        account["revision"].as_str().unwrap(),
    ]);
    assert_eq!(counts(f)["refresh"], 1);
    denials::denied_tools(f, agent).await;
    f.stop();
    f.start_with_keys(
        process::DAEMON,
        Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="),
        Some(KEY),
    )
    .await;
    receiving::prepare(f, agent).await;
    receiving::use_both(f, agent).await;
    assert_eq!(counts(f)["tool"], 8);
}

fn retire(f: &Fixture) {
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
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "reader"])["state"],
        "reconnect_required"
    );
}
