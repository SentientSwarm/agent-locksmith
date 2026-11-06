use super::*;
pub(super) async fn standard(f: &fixture::Fixture, t: &str) {
    let session = wire::open(f, t).await;
    let listed = standard_rpc(
        f,
        t,
        &session,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    let list = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(list.len(), 4);
    for (i, entry) in list.iter().enumerate() {
        standard_one(f, t, &session, i, entry).await;
    }
}
async fn standard_one(f: &fixture::Fixture, t: &str, session: &str, i: usize, entry: &Value) {
    assert_eq!(
        entry["_meta"]["locksmith.dev/native-contract"]["policy"],
        "finite-v2"
    );
    let name = entry["name"].as_str().unwrap();
    let result=standard_rpc(f,t,session,json!({"jsonrpc":"2.0","id":2+i*2,"method":"tools/call","params":{"name":name,"arguments":{}}})).await;
    assert!(result.get("result").is_some(), "{result}");
    let denied=standard_rpc(f,t,session,json!({"jsonrpc":"2.0","id":3+i*2,"method":"tools/call","params":{"name":name,"arguments":{"unknown":true}}})).await;
    assert!(denied.get("error").is_some());
}
async fn standard_rpc(f: &fixture::Fixture, t: &str, session: &str, body: Value) -> Value {
    parse(wire::post(f, t, Some(session), body).await).await
}
pub(super) async fn compact(f: &fixture::Fixture, t: &str) {
    let session = compact_open(f, t).await;
    let found = payload(call(f, t, &session, 2, "search", json!({"query":"record"})).await);
    assert_eq!(found["matches"].as_array().unwrap().len(), 4);
    for (i, entry) in found["matches"].as_array().unwrap().iter().enumerate() {
        compact_one(f, t, &session, i, entry).await;
    }
}
async fn compact_open(f: &fixture::Fixture, t: &str) -> String {
    let response = post(f, t, None, wire::init()).await;
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    response.text().await.unwrap();
    post(
        f,
        t,
        Some(&session),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    rpc(
        f,
        t,
        &session,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    session
}
async fn compact_one(f: &fixture::Fixture, t: &str, session: &str, i: usize, entry: &Value) {
    let d = payload(
        call(
            f,
            t,
            session,
            3 + i as u64 * 2,
            "describe",
            json!({"handle":entry["handle"]}),
        )
        .await,
    );
    assert_eq!(d["native_contract"]["policy"], "finite-v2");
    let args = if d["name"] != "read_record" {
        json!({})
    } else {
        json!({"key":"choice-44","flag":true})
    };
    let result=call(f,t,session,4+i as u64*2,"invoke",json!({"handle":entry["handle"],"contract_digest":entry["contract_digest"],"arguments":args})).await;
    assert!(result.get("result").is_some(), "{result}");
}
