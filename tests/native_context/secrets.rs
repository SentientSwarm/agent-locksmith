use super::{flow, process, support as s};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn context_secret_is_refused_before_persistence_response_or_receiving_io() {
    let (mut f, receiver, a) = s::setup().await;
    let id = a["public_id"].as_str().unwrap();
    let secret = "synthetic-context-quote\"slash\\canary";
    s::stored(&f, id, secret);
    let state = flow::observe(&f, id);
    let counts = std::fs::read(f.path().join("counts.json")).unwrap();
    let input = request(&state, json!({"workspace":secret}));
    let file = flow::write(&f, input.clone());
    let out = process::run(f.command(&[
        "tool", "mcp", "review", "native", "--agent", id, "--file", &file,
    ]));
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&out.stderr).contains(secret));
    assert_eq!(std::fs::read(f.path().join("counts.json")).unwrap(), counts);
    assert_no_review(&f, secret).await;
    missing_custody(&mut f, id, secret, &counts).await;
    receiver.stop();
}
fn request(state: &Value, context: Value) -> Value {
    let entry = state["observation"]["manifest"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["tool"]["name"] == "read_record")
        .unwrap();
    json!({"source":state["source"],"generation":state["observation"]["generation"],"name":"read_record",
        "observed_digest":entry["observed_digest"],"effect":"read","context":context})
}
async fn assert_no_review(f: &super::fixture::Fixture, secret: &str) {
    let pool = s::pool(f).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM native_reviews")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let audit: Vec<String> = sqlx::query_scalar("SELECT coalesce(details,'') FROM audit")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(!audit.join("").contains(secret));
    let log = std::fs::read_to_string(f.path().join("daemon.log")).unwrap();
    assert!(!log.contains(secret));
    assert!(s::effects(f).is_empty());
    pool.close().await;
}

async fn missing_custody(f: &mut super::fixture::Fixture, id: &str, secret: &str, counts: &[u8]) {
    f.stop();
    f.start(process::DAEMON).await;
    let file = flow::write(f, request(&flow::show(f, id), json!({"workspace":"safe"})));
    let out = process::run(f.command(&[
        "tool", "mcp", "review", "native", "--agent", id, "--file", &file,
    ]));
    assert!(!out.status.success());
    assert_no_review(f, secret).await;
    assert_eq!(std::fs::read(f.path().join("counts.json")).unwrap(), counts);
    f.stop();
}
