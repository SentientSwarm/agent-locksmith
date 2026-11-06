use super::{fixture::Fixture, flow, process, receiver, wire};
use serde_json::{Value, json};
use std::{io::Write, process::Stdio};

pub async fn setup() -> (Fixture, receiver::Receiver, Value) {
    let mut f = Fixture::new();
    receiver::configure(&f);
    manifest(&f);
    let upstream = receiver::Receiver::start(&f);
    f.start_with_key(
        process::DAEMON,
        Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
    )
    .await;
    let a = f.enroll(
        "context-agent",
        &format!("https://localhost:{}/mcp", upstream.port),
    );
    (f, upstream, a)
}
pub fn manifest(f: &Fixture) {
    let schema = json!({"type":"object","properties":{"workspace":{"type":"string"},"key":{"type":"string"}},"required":["workspace","key"],"additionalProperties":false});
    std::fs::write(f.path().join("manifest.json"),json!({"tools":[
        {"name":"read_record","inputSchema":schema},
        {"name":"plain_record","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}
    ]}).to_string()).unwrap();
}
pub fn review(f: &Fixture, id: &str, context: Value, name: &str) -> Value {
    let s = flow::observe(f, id);
    let entry = s["observation"]["manifest"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["tool"]["name"] == name)
        .unwrap();
    let file = flow::write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"],
        "name":name,"effect":"read","observed_digest":entry["observed_digest"],"context":context}),
    );
    f.op(&[
        "tool", "mcp", "review", "native", "--agent", id, "--file", &file,
    ])
}
pub fn grant(f: &Fixture, id: &str, r: &Value) {
    replace(
        f,
        id,
        json!([{"name":r["contract"]["tool"]["name"],"contract_digest":r["contract_digest"]}]),
    );
}
pub fn replace(f: &Fixture, id: &str, tools: Value) {
    let s = flow::show(f, id);
    let file = flow::write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"],
        "revision":s["grant_revision"],"tools":tools}),
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
pub async fn rpc(
    f: &Fixture,
    a: &Value,
    session: &str,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    let response = wire::post(
        f,
        a["token"].as_str().unwrap(),
        Some(session),
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
    )
    .await;
    let body = response.text().await.unwrap();
    serde_json::from_str(
        body.lines()
            .find_map(|l| l.strip_prefix("data: "))
            .unwrap_or(&body),
    )
    .unwrap()
}
pub async fn open(f: &Fixture, a: &Value) -> String {
    let s = wire::open(f, a["token"].as_str().unwrap()).await;
    let listed = rpc(f, a, &s, 1, "tools/list", json!({})).await;
    assert!(listed["result"]["tools"].is_array(), "{listed}");
    s
}
pub async fn call(f: &Fixture, a: &Value, s: &str, id: u64, args: Value) -> Value {
    rpc(
        f,
        a,
        s,
        id,
        "tools/call",
        json!({"name":"read_record","arguments":args}),
    )
    .await
}
pub fn effects(f: &Fixture) -> Vec<Value> {
    std::fs::read(f.path().join("effects.json"))
        .map(|b| serde_json::from_slice(&b).unwrap())
        .unwrap_or_default()
}
pub async fn pool(f: &Fixture) -> sqlx::SqlitePool {
    sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db")),
    )
    .await
    .unwrap()
}
pub fn stored(f: &Fixture, id: &str, secret: &str) -> String {
    let mut c = f.command(&[
        "agent",
        "set-credential",
        id,
        "native",
        "--stored-bearer-stdin",
    ]);
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = process::Guard(c.spawn().unwrap());
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(secret.as_bytes())
        .unwrap();
    assert!(process::wait(&mut child.0).success());
    f.op(&["agent", "credentials", "list", id])[0]["auth_spec"]["secret_ref"]
        .as_str()
        .unwrap()
        .into()
}

pub fn behavior(f: &Fixture, value: Value) {
    std::fs::write(f.path().join("behavior.json"), value.to_string()).unwrap();
}
pub async fn audit(f: &Fixture, event: &str) -> Vec<Value> {
    let pool = pool(f).await;
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit WHERE event=? ORDER BY id")
            .bind(event)
            .fetch_all(&pool)
            .await
            .unwrap();
    pool.close().await;
    rows.iter()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
