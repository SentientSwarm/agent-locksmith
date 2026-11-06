#![allow(dead_code)]
#[path = "native_process/fixture.rs"]
mod fixture;
#[path = "native_preparation/process_flow.rs"]
mod flow;
#[path = "native_process/observations.rs"]
mod observations;
#[path = "native_process/pki.rs"]
mod pki;
#[path = "explicit_binding_smoke/process.rs"]
mod process;
#[path = "native_dispatch/receiver.rs"]
mod receiver;
#[path = "native_process/wire.rs"]
mod wire;
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compact_requires_describe_then_uses_committed_dispatch() {
    let mut f = fixture::Fixture::new();
    receiver::configure(&f);
    let upstream = receiver::Receiver::start(&f);
    std::fs::write(
        f.path().join("mcp.json"),
        json!({"protocol_version":"2025-11-25","allow_private_destination":true,"compact":true})
            .to_string(),
    )
    .unwrap();
    f.start(process::DAEMON).await;
    let a = f.enroll(
        "compact",
        &format!("https://localhost:{}/mcp", upstream.port),
    );
    grant(&f, a["public_id"].as_str().unwrap());
    let token = a["token"].as_str().unwrap();
    let response = post(&f, token, None, wire::init()).await;
    assert_eq!(response.status(), 200);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(response.text().await.unwrap().contains("2025-11-25"));
    assert_eq!(
        post(
            &f,
            token,
            Some(&session),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .await
        .status(),
        202
    );
    let early = call(&f, token, &session, 1, "search", json!({"query":"read"})).await;
    assert_eq!(early["error"]["data"]["code"], "tools_list_required");
    let list = rpc(
        &f,
        token,
        &session,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    assert_eq!(
        list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["search", "describe", "invoke"]
    );
    let search = payload(call(&f, token, &session, 3, "search", json!({"query":"read"})).await);
    let entry = &search["matches"][0];
    let args = json!({"handle":entry["handle"],"contract_digest":entry["contract_digest"],"arguments":{"key":"safe-record"}});
    assert_eq!(
        call(&f, token, &session, 4, "invoke", args.clone()).await["error"]["data"]["code"],
        "schema_required"
    );
    assert!(!f.path().join("effects.json").exists());
    let description = payload(
        call(
            &f,
            token,
            &session,
            5,
            "describe",
            json!({"handle":entry["handle"]}),
        )
        .await,
    );
    assert_eq!(description["name"], "read_record");
    assert_eq!(description["effect"], "mixed");
    assert_eq!(description["contract_digest"], entry["contract_digest"]);
    let result = call(&f, token, &session, 6, "invoke", args).await;
    assert_eq!(
        result["result"]["structuredContent"]["account"], "None",
        "{result}"
    );
    let effects: Value =
        serde_json::from_slice(&std::fs::read(f.path().join("effects.json")).unwrap()).unwrap();
    assert_eq!(effects, json!([{"account":"None","committed":1}]));
    f.stop();
    upstream.stop();
}
fn grant(f: &fixture::Fixture, id: &str) {
    let s = flow::observe(f, id);
    let file = flow::write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"],"name":"read_record","observed_digest":s["observation"]["manifest"]["tools"][0]["observed_digest"],"effect":"mixed"}),
    );
    let r = f.op(&[
        "tool", "mcp", "review", "native", "--agent", id, "--file", &file,
    ]);
    let file = flow::write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"],"revision":s["grant_revision"],"tools":[{"name":"read_record","contract_digest":r["contract_digest"]}]}),
    );
    f.op(&[
        "agent",
        "mcp-grants",
        "replace",
        "native",
        "--agent",
        id,
        "--file",
        &file,
    ]);
}
async fn post(f: &fixture::Fixture, t: &str, s: Option<&str>, body: Value) -> reqwest::Response {
    let mut r = f
        .http
        .post(f.url("/mcp/native/compact"))
        .bearer_auth(t)
        .header("accept", "application/json, text/event-stream")
        .json(&body);
    if let Some(s) = s {
        r = r
            .header("mcp-session-id", s)
            .header("mcp-protocol-version", "2025-11-25");
    }
    r.send().await.unwrap()
}
async fn rpc(f: &fixture::Fixture, t: &str, s: &str, body: Value) -> Value {
    let response = post(f, t, Some(s), body).await;
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap();
    serde_json::from_str(
        text.lines()
            .find_map(|l| l.strip_prefix("data: "))
            .unwrap_or(&text),
    )
    .unwrap()
}
async fn call(f: &fixture::Fixture, t: &str, s: &str, id: u64, name: &str, args: Value) -> Value {
    rpc(f,t,s,json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}})).await
}
fn payload(v: Value) -> Value {
    serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[path = "native_compact/boundary.rs"]
mod boundary;

#[path = "native_compact/prior.rs"]
mod prior;
