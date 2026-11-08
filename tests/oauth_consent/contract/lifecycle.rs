use super::*;

pub async fn run(service: bool) {
    let (mut f, t) = journey::ready(service, false, false).await;
    let created = setup::connect_contract(&f, "reader");
    assert_eq!(slack::setup::authorize(&f, &created, false).await, 200);
    let agent = f.op(&[
        "agent",
        "register",
        "--name",
        "lifecycle",
        "--allowlist",
        "fixture",
    ]);
    slack::receiving::select(&f, &agent);
    slack::receiving::prepare(&f, &agent).await;
    slack::receiving::use_both(&f, &agent).await;
    refresh_restart(&mut f, &agent).await;
    disconnect_reconnect(&f, &agent).await;
    cancelled(&f).await;
    assert_eq!(counts(&f)["tool"], 8);
    f.stop();
    t.stop();
    println!(
        "generic service={service}: refresh/restart, stale CAS, both-facade disconnect denial, explicit reconnect/selection, cancel, 8 effects; joined"
    );
}
async fn refresh_restart(f: &mut Fixture, agent: &Value) {
    let before = view(f);
    f.op(&[
        "oauth",
        "refresh",
        "fixture",
        "--label",
        "reader",
        "--if-match",
        before["revision"].as_str().unwrap(),
    ]);
    stale(f, agent, &before);
    f.stop();
    f.start_with_keys(
        process::DAEMON,
        Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="),
        Some(KEY),
    )
    .await;
    assert_eq!(view(f)["verified_subject"], before["verified_subject"]);
    assert_eq!(view(f)["granted_scope"], before["granted_scope"]);
}
fn view(f: &Fixture) -> Value {
    f.op(&["oauth", "account-status", "fixture", "--label", "reader"])
}
fn stale(f: &Fixture, agent: &Value, old: &Value) {
    let before = counts(f);
    let result = process::run(f.command(&[
        "agent",
        "select-oauth",
        agent["public_id"].as_str().unwrap(),
        "fixture",
        "--label",
        "reader",
        "--if-match",
        old["revision"].as_str().unwrap(),
    ]));
    assert!(!result.status.success());
    assert_eq!(counts(f), before);
}
async fn sessions(f: &Fixture, agent: &Value) -> Vec<(String, String, Value)> {
    let mut sessions = Vec::new();
    for compact in [false, true] {
        let (path, session) = native::open(f, agent, compact).await;
        let params = if compact {
            slack::receiving::compact_params(f, agent, &path, &session, "read_thread", 0).await
        } else {
            json!({"name":"read_thread","arguments":{"channel":"CPUBLIC1"}})
        };
        sessions.push((path, session, params));
    }
    sessions
}
async fn disconnect_reconnect(f: &Fixture, agent: &Value) {
    slack::receiving::prepare(f, agent).await;
    let sessions = sessions(f, agent).await;
    let old = view(f);
    f.op(&[
        "oauth",
        "disconnect",
        "fixture",
        "--label",
        "reader",
        "--if-match",
        old["revision"].as_str().unwrap(),
    ]);
    denied(f, agent, sessions).await;
    reconnect(f, agent, &old).await;
}
async fn reconnect(f: &Fixture, agent: &Value, old: &Value) {
    let created = setup::connect_contract(f, "reader");
    assert_eq!(slack::setup::authorize(f, &created, false).await, 200);
    assert_eq!(view(f)["state"], "connected_unbound");
    stale(f, agent, old);
    slack::receiving::select(f, agent);
    slack::receiving::prepare(f, agent).await;
    slack::receiving::use_both(f, agent).await;
}
async fn denied(f: &Fixture, agent: &Value, sessions: Vec<(String, String, Value)>) {
    let before = counts(f);
    for (path, session, params) in sessions {
        let (status, value, _) = native::rpc(
            f,
            agent,
            &path,
            Some(&session),
            json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":params}),
        )
        .await;
        assert!(
            status != 200 || value.get("error").is_some() || value["result"]["isError"] == true
        );
        f.http
            .delete(f.url(&path))
            .bearer_auth(agent["token"].as_str().unwrap())
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", "2025-11-25")
            .send()
            .await
            .unwrap();
    }
    assert_eq!(counts(f)["tool"], before["tool"]);
}
async fn cancelled(f: &Fixture) {
    let created = setup::connect_contract(f, "cancelled");
    let callback = slack::setup::issue(f, &created, false).await;
    f.op(&[
        "oauth",
        "cancel",
        "fixture",
        created["attempt_id"].as_str().unwrap(),
    ]);
    let before = counts(f);
    assert_eq!(f.http.get(callback).send().await.unwrap().status(), 400);
    assert_eq!(counts(f), before);
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "cancelled"])["state"],
        "absent"
    );
}
