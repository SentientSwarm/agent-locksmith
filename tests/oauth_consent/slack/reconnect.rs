use super::*;

pub(super) async fn run(f: &Fixture, agent: &Value) {
    let before = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    let (path, session) = native::open(f, agent, false).await;
    f.op(&[
        "oauth",
        "disconnect",
        "fixture",
        "--label",
        "reader",
        "--if-match",
        before["revision"].as_str().unwrap(),
    ]);
    let created = setup::connect_slack(f, "reader");
    assert_eq!(setup::authorize(f, &created, false).await, 200);
    let after = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    assert!(
        after["account_generation"].as_i64().unwrap()
            > before["account_generation"].as_i64().unwrap()
    );
    let (status, result, _) = native::rpc(f, agent, &path, Some(&session),
        json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"search_messages","arguments":{"channel":"CPUBLIC1"}}})).await;
    assert!(status != 200 || result.get("error").is_some() || result["result"]["isError"] == true);
    assert_eq!(counts(f)["tool"], 8, "old session cannot revive authority");
    receiving::select(f, agent);
    denials::denied_tools(f, agent).await;
    receiving::prepare(f, agent).await;
    receiving::use_both(f, agent).await;
    assert_eq!(counts(f)["tool"], 12);
}
