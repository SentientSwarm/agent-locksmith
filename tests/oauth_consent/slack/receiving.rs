use super::*;
const NAMES: [&str; 2] = ["search_messages", "read_thread"];

pub(in crate::consent) fn select(f: &Fixture, agent: &Value) {
    let status = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    f.op(&[
        "agent",
        "select-oauth",
        agent["public_id"].as_str().unwrap(),
        "fixture",
        "--label",
        "reader",
        "--if-match",
        status["revision"].as_str().unwrap(),
    ]);
}

pub(in crate::consent) async fn prepare(f: &Fixture, agent: &Value) {
    let id = agent["public_id"].as_str().unwrap();
    let path = format!("/admin/operator/tools/fixture/mcp/observations/{id}");
    let (status, before) = request(f, "GET", &path, None).await;
    assert_eq!(status, 200, "{before}");
    let (status, state) = request(
        f,
        "POST",
        &path,
        Some(json!({"source":before["source"],"generation":before["observation"]["generation"]})),
    )
    .await;
    assert_eq!(status, 200, "{state}");
    assert_eq!(
        state["observation"]["manifest"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let mut tools = Vec::new();
    for name in NAMES {
        tools.push(review(f, id, &state, name).await);
    }
    let (status,result)=request(f,"PUT",&format!("/admin/operator/agents/{id}/mcp-grants/fixture"),Some(json!({"source":state["source"],"generation":state["observation"]["generation"],"revision":state["grant_revision"],"tools":tools}))).await;
    assert_eq!(status, 200, "{result}");
}

async fn review(f: &Fixture, id: &str, state: &Value, name: &str) -> Value {
    let tool = state["observation"]["manifest"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["tool"]["name"] == name)
        .unwrap();
    let (status,result)=request(f,"PUT",&format!("/admin/operator/tools/fixture/mcp/reviews/{id}"),Some(json!({"source":state["source"],"generation":state["observation"]["generation"],"name":name,"observed_digest":tool["observed_digest"],"effect":"read","contract_policy":"finite-v2"}))).await;
    assert_eq!(status, 200, "{result}");
    json!({"name":name,"contract_digest":result["contract_digest"]})
}

pub(in crate::consent) async fn use_both(f: &Fixture, agent: &Value) {
    for compact in [false, true] {
        let (path, session) = native::open(f, agent, compact).await;
        calls(f, agent, &path, &session, compact).await;
        assert!(
            f.http
                .delete(f.url(&path))
                .bearer_auth(agent["token"].as_str().unwrap())
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25")
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
    }
}

pub(in crate::consent) async fn compact_params(
    f: &Fixture,
    agent: &Value,
    path: &str,
    session: &str,
    name: &str,
    offset: u64,
) -> Value {
    let (_,search,_)=native::rpc(f,agent,path,Some(session),json!({"jsonrpc":"2.0","id":3+offset,"method":"tools/call","params":{"name":"search","arguments":{"query":name,"limit":8}}})).await;
    let result: Value =
        serde_json::from_str(search["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let matched = &result["matches"][0];
    let (_,described,_)=native::rpc(f,agent,path,Some(session),json!({"jsonrpc":"2.0","id":4+offset,"method":"tools/call","params":{"name":"describe","arguments":{"handle":matched["handle"]}}})).await;
    assert!(described["result"].is_object());
    json!({"name":"invoke","arguments":{"handle":matched["handle"],"contract_digest":matched["contract_digest"],"arguments":{"channel":"CPUBLIC1"}}})
}

async fn calls(f: &Fixture, agent: &Value, path: &str, session: &str, compact: bool) {
    for (index, name) in NAMES.into_iter().enumerate() {
        let params = if compact {
            compact_params(f, agent, path, session, name, index as u64 * 4).await
        } else {
            json!({"name":name,"arguments":{"channel":"CPUBLIC1"}})
        };
        let (status, value, _) = native::rpc(
            f,
            agent,
            path,
            Some(session),
            json!({"jsonrpc":"2.0","id":5+index*4,"method":"tools/call","params":params}),
        )
        .await;
        assert_eq!(status, 200);
        assert_ne!(value["result"]["isError"], true, "{value}");
        let result: Value =
            serde_json::from_str(value["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(result["account"], "X");
        assert_eq!(result["channel"], "CPUBLIC1");
    }
}
