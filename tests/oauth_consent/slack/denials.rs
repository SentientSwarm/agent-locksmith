use super::*;

pub(super) async fn denied_tools(f: &Fixture, agent: &Value) {
    let before = counts(f)["tool"].clone();
    for compact in [false, true] {
        let (path, session) = native::open(f, agent, compact).await;
        let params = if compact {
            json!({"name":"search","arguments":{"query":"search_messages","limit":8}})
        } else {
            json!({"name":"search_messages","arguments":{"channel":"CPUBLIC1"}})
        };
        let (_, result, _) = native::rpc(
            f,
            agent,
            &path,
            Some(&session),
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":params}),
        )
        .await;
        check_denied(compact, &result);
    }
    assert_eq!(
        counts(f)["tool"],
        before,
        "unreviewed/stale grants have no effect"
    );
}

fn check_denied(compact: bool, result: &Value) {
    if compact {
        let value: Value =
            serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(value["matches"], json!([]));
    } else {
        assert!(result.get("error").is_some() || result["result"]["isError"] == true);
    }
}
