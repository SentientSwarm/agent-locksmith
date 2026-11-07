use super::{flow, support as s};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_context_dispatch_projects_injects_and_preserves_shared_x_y_none() {
    let (mut f, receiver, a) = s::setup().await;
    let url = format!("https://localhost:{}/mcp", receiver.port);
    let shared = f.enroll("shared-context", &url);
    let none = f.enroll("none-context", &url);
    let id = a["public_id"].as_str().unwrap();
    let reference = s::stored(&f, id, "fixture-account-x");
    f.op(&[
        "agent",
        "set-credential",
        shared["public_id"].as_str().unwrap(),
        "native",
        "--stored-bearer-ref",
        &reference,
    ]);
    success(&f, &a, "X").await;
    s::stored(&f, id, "fixture-account-y");
    success(&f, &shared, "X").await;
    success(&f, &a, "Y").await;
    success(&f, &none, "None").await;
    assert_eq!(s::effects(&f).len(), 4);
    f.stop();
    receiver.stop();
}
async fn success(f: &super::fixture::Fixture, a: &Value, account: &str) {
    let id = a["public_id"].as_str().unwrap();
    let r = s::review(f, id, json!({"workspace":"fixed-scope"}), "read_record");
    s::grant(f, id, &r);
    let session = s::open(f, a).await;
    let listed = s::rpc(f, a, &session, 2, "tools/list", json!({})).await;
    assert!(
        listed["result"]["tools"][0]["inputSchema"]["properties"]
            .get("workspace")
            .is_none()
    );
    let result = s::call(f, a, &session, 3, json!({"key":"record"})).await;
    assert_eq!(result["result"]["content"][0]["text"], account, "{result}");
    let effect = s::effects(f).pop().unwrap();
    assert_eq!(
        effect["arguments"],
        json!({"key":"record","workspace":"fixed-scope"})
    );
    assert_eq!(effect["admission"]["contract_digest"], r["contract_digest"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_overrides_denied_and_candidate_context_needs_deliberate_grant() {
    let (mut f, receiver, a) = s::setup().await;
    let id = a["public_id"].as_str().unwrap();
    let old = s::review(&f, id, json!({"workspace":"old"}), "read_record");
    s::grant(&f, id, &old);
    let session = s::open(&f, &a).await;
    overrides(&f, &a, &session).await;
    let before = flow::show(&f, id);
    let new = s::review(&f, id, json!({"workspace":"new"}), "read_record");
    assert_eq!(
        flow::show(&f, id)["grant_revision"],
        before["grant_revision"]
    );
    assert!(s::call(&f, &a, &session, 10, json!({"key":"read"})).await["result"].is_object());
    assert_eq!(s::effects(&f)[0]["arguments"]["workspace"], "old");
    s::grant(&f, id, &new);
    assert!(s::call(&f, &a, &session, 11, json!({"key":"read"})).await["error"].is_object());
    let fresh = s::open(&f, &a).await;
    assert!(s::call(&f, &a, &fresh, 2, json!({"key":"read"})).await["result"].is_object());
    assert_eq!(s::effects(&f)[1]["arguments"]["workspace"], "new");
    f.stop();
    receiver.stop();
}
async fn overrides(f: &super::fixture::Fixture, a: &Value, session: &str) {
    for (i, value) in [json!("old"), json!("other"), Value::Null]
        .into_iter()
        .enumerate()
    {
        let r = s::call(
            f,
            a,
            session,
            2 + i as u64,
            json!({"workspace":value,"key":"read"}),
        )
        .await;
        assert_eq!(r["error"]["data"]["code"], "protected_argument", "{r}");
    }
    assert!(s::effects(f).is_empty());
    let pool = s::pool(f).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    pool.close().await;
}
