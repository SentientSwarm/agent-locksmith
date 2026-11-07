#[path = "native/fixture.rs"]
mod fixture;
use fixture::*;
use serde_json::{Value, json};

#[tokio::test]
async fn initialized_lifecycle_has_no_tool_authority_and_no_http_route() {
    let f = Fixture::new("").await;
    let session = f.open().await;
    assert_eq!(
        rpc(f.call(&session, 1, "ping").await).await["result"],
        json!({})
    );
    assert_eq!(
        rpc(f.call(&session, 2, "tools/list").await).await["result"]["tools"],
        json!([])
    );
    tool_denied(&f, &session).await;
    assert_eq!(
        f.request("/api/native/mcp", "POST", init(4), None)
            .await
            .status(),
        404
    );
    assert_eq!(
        f.request("/mcp/native", "DELETE", Value::Null, Some(&session))
            .await
            .status(),
        202
    );
    released(&f).await;
    assert_eq!(
        f.runtime.snapshot().workers_created,
        f.runtime.snapshot().workers_joined
    );
}
#[tokio::test]
async fn completed_and_initialize_request_ids_cannot_replay() {
    let f = Fixture::new("").await;
    let session = f.open().await;
    assert_eq!(f.call(&session, 0, "ping").await.status(), 409);
    released(&f).await;
    let session = f.open().await;
    let _ = rpc(f.call(&session, 1, "ping").await).await;
    assert_eq!(f.call(&session, 1, "ping").await.status(), 409);
    released(&f).await;
}
#[tokio::test]
async fn current_binding_epoch_rejects_same_timestamp_aba() {
    let f = Fixture::new("").await;
    let session = f.open().await;
    f.bindings.delete(f.agent_id, "native").await.unwrap();
    f.bindings
        .set(
            f.agent_id,
            "native",
            &agent_locksmith::registrations::AuthSpec::None,
        )
        .await
        .unwrap();
    assert_eq!(f.call(&session, 1, "ping").await.status(), 404);
    released(&f).await;
    let session = f.open().await;
    let _ = rpc(f.call(&session, 1, "ping").await).await;
    f.runtime.shutdown().await;
}
#[tokio::test]
async fn one_process_cap_covers_different_connection_routes_and_recovers() {
    let f = Fixture::new("mcp:\n  sessions: 1\n").await;
    let session = f.open().await;
    let response = f.request("/mcp/other", "POST", init(0), None).await;
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers()["retry-after"], "1");
    assert_eq!(f.runtime.snapshot().workers_created, 1);
    drop(
        f.request("/mcp/native", "DELETE", Value::Null, Some(&session))
            .await,
    );
    released(&f).await;
    let response = f.request("/mcp/other", "POST", init(0), None).await;
    assert_eq!(response.status(), 200);
    drop(response);
    released(&f).await;
}
#[tokio::test]
async fn protocol_roundtrip_clears_selections_and_connection_grants() {
    let f = Fixture::new("").await;
    let session = f.open().await;
    let mut r = f.repo.get("native").await.unwrap().unwrap();
    r.protocol = agent_locksmith::registrations::Protocol::Http;
    r.mcp = None;
    f.repo.upsert(&r).await.unwrap();
    f.refresh().await;
    assert!(
        f.bindings
            .get(f.agent_id, "native")
            .await
            .unwrap()
            .is_none()
    );
    let agent = f.agents.get_by_name("caller").await.unwrap().unwrap();
    assert!(!agent.tool_allowlist.unwrap().contains(&"native".to_owned()));
    f.repo.upsert(&native("native")).await.unwrap();
    f.refresh().await;
    assert_eq!(f.call(&session, 1, "ping").await.status(), 403);
    f.runtime.shutdown().await;
}

async fn tool_denied(f: &Fixture, session: &str) {
    let call = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"forged","arguments":{}}});
    assert_eq!(
        rpc(f.request("/mcp/native", "POST", call, Some(session)).await).await["error"]["data"]["code"],
        "tool_not_approved"
    );
}
