use super::{fixture::Fixture, flow, process, receiver, support as s, wire};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pre-context schema-14 daemon via LOCKSMITH_CONTEXT_PRIOR_DAEMON; holds only while the current schema is 14 (through 4b777cb)"]
async fn actual_schema14_context_downgrade_is_fail_closed_and_reupgrade_preserves_revoke() {
    let prior = std::env::var("LOCKSMITH_CONTEXT_PRIOR_DAEMON").unwrap();
    let mut f = Fixture::new();
    receiver::configure(&f);
    s::manifest(&f);
    let receiver = receiver::Receiver::start(&f);
    f.start(&prior).await;
    let a = f.enroll(
        "context-upgrade",
        &format!("https://localhost:{}/mcp", receiver.port),
    );
    let id = a["public_id"].as_str().unwrap();
    let empty = prior_granted(&f, &a).await;
    let old_bytes = reviews(&f).await;
    f.stop();
    f.start(process::DAEMON).await;
    assert_eq!(reviews(&f).await, old_bytes);
    flow::observe(&f, id);
    plain(&f, &a).await;
    let context = s::review(&f, id, json!({"workspace":"fixed"}), "read_record");
    let mixed = json!([entry(&empty), entry(&context)]);
    s::replace(&f, id, mixed.clone());
    let session = s::open(&f, &a).await;
    assert!(s::call(&f, &a, &session, 2, json!({"key":"read"})).await["result"].is_object());
    let bytes = reviews(&f).await;
    downgrade(&mut f, &a, &prior, &empty, &context, &mixed, &bytes).await;
    reupgrade(&mut f, &a, &mixed, &bytes).await;
    f.stop();
    receiver.stop();
}
fn entry(r: &Value) -> Value {
    json!({"name":r["contract"]["tool"]["name"],"contract_digest":r["contract_digest"]})
}
fn empty_review(f: &Fixture, id: &str) -> Value {
    let state = flow::observe(f, id);
    let entry = state["observation"]["manifest"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["tool"]["name"] == "plain_record")
        .unwrap();
    let file = flow::write(
        f,
        json!({"source":state["source"],"generation":state["observation"]["generation"],"name":"plain_record","effect":"read","observed_digest":entry["observed_digest"]}),
    );
    f.op(&[
        "tool", "mcp", "review", "native", "--agent", id, "--file", &file,
    ])
}
async fn plain(f: &Fixture, a: &Value) {
    let session = s::open(f, a).await;
    let r = s::rpc(
        f,
        a,
        &session,
        2,
        "tools/call",
        json!({"name":"plain_record","arguments":{}}),
    )
    .await;
    assert_eq!(r["result"]["content"][0]["text"], "None", "{r}");
}
async fn old_denies(f: &Fixture, a: &Value) {
    let session = wire::open(f, a["token"].as_str().unwrap()).await;
    let listed = s::rpc(f, a, &session, 1, "tools/list", json!({})).await;
    assert_eq!(
        listed["error"]["data"]["code"], "review_invalid",
        "{listed}"
    );
    assert!(s::call(f, a, &session, 2, json!({"key":"read"})).await["error"].is_object());
}
fn old_refuses_context_write(f: &Fixture, id: &str) {
    let state = flow::show(f, id);
    let item = state["observation"]["manifest"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["tool"]["name"] == "read_record")
        .unwrap();
    let file = flow::write(
        f,
        json!({"source":state["source"],"generation":state["observation"]["generation"],"name":"read_record","observed_digest":item["observed_digest"],"effect":"read","context":{"workspace":"fixed"}}),
    );
    assert!(
        !process::run(f.command(&[
            "tool", "mcp", "review", "native", "--agent", id, "--file", &file
        ]))
        .status
        .success()
    );
}
async fn reviews(f: &Fixture) -> Vec<String> {
    let pool = s::pool(f).await;
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 14);
    let rows = sqlx::query_scalar(
        "SELECT contract_digest||':'||contract FROM native_reviews ORDER BY contract_digest",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    pool.close().await;
    rows
}

async fn downgrade(
    f: &mut Fixture,
    a: &Value,
    prior: &str,
    empty: &Value,
    context: &Value,
    mixed: &Value,
    bytes: &Vec<String>,
) {
    let id = a["public_id"].as_str().unwrap();
    f.stop();
    f.start(prior).await;
    flow::observe(f, id);
    assert_eq!(&reviews(f).await, bytes);
    old_refuses_context_write(f, id);
    for tools in [json!([entry(context)]), mixed.clone()] {
        s::replace(f, id, tools);
        old_denies(f, a).await;
    }
    assert_eq!(s::effects(f).len(), 3);
    s::grant(f, id, empty);
    plain(f, a).await;
    s::replace(f, id, mixed.clone());
    s::replace(f, id, json!([]));
}
async fn reupgrade(f: &mut Fixture, a: &Value, mixed: &Value, bytes: &Vec<String>) {
    let id = a["public_id"].as_str().unwrap();
    f.stop();
    f.start(process::DAEMON).await;
    flow::observe(f, id);
    assert_eq!(&reviews(f).await, bytes);
    assert_eq!(flow::show(f, id)["tools"], json!([]));
    let session = s::open(f, a).await;
    assert!(s::call(f, a, &session, 2, json!({"key":"read"})).await["error"].is_object());
    assert_eq!(s::effects(f).len(), 4);
    s::replace(f, id, mixed.clone());
    let session = s::open(f, a).await;
    assert!(s::call(f, a, &session, 2, json!({"key":"read"})).await["result"].is_object());
    assert_eq!(s::effects(f).len(), 5);
}

async fn prior_granted(f: &Fixture, a: &Value) -> Value {
    let id = a["public_id"].as_str().unwrap();
    let empty = empty_review(f, id);
    s::grant(f, id, &empty);
    plain(f, a).await;
    empty
}
