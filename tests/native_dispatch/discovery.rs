use super::{fixture::Fixture, flow, process, receiver, wire};
use serde_json::{Value, json};

pub fn grant(f: &Fixture, agent: &str) {
    let s = flow::observe(f, agent);
    let file = flow::write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"],
        "name":"read_record","observed_digest":s["observation"]["manifest"]["tools"][0]["observed_digest"],"effect":"read"}),
    );
    let r = f.op(&[
        "tool", "mcp", "review", "native", "--agent", agent, "--file", &file,
    ]);
    let file = flow::write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"],
        "revision":s["grant_revision"],"tools":[{"name":"read_record","contract_digest":r["contract_digest"]}]}),
    );
    f.op(&[
        "agent",
        "mcp-grants",
        "replace",
        "native",
        "--agent",
        agent,
        "--file",
        &file,
    ]);
}
pub async fn list(f: &Fixture, token: &str, session: &str, id: u64) -> Value {
    let r = wire::post(
        f,
        token,
        Some(session),
        json!({"jsonrpc":"2.0","id":id,"method":"tools/list"}),
    )
    .await;
    let body = r.text().await.unwrap();
    serde_json::from_str(
        body.lines()
            .find_map(|l| l.strip_prefix("data: "))
            .unwrap_or(&body),
    )
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_daemon_lists_reviewed_selected_tool() {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let upstream = receiver::Receiver::start(&f);
    f.start(process::DAEMON).await;
    let agent = f.enroll(
        "consumer",
        &format!("https://localhost:{}/mcp", upstream.port),
    );
    grant(&f, agent["public_id"].as_str().unwrap());
    let token = agent["token"].as_str().unwrap();
    let session = wire::open(&f, token).await;
    let result = list(&f, token, &session, 1).await;
    assert_eq!(
        result["result"]["tools"][0]["name"], "read_record",
        "reviewed tool must be discoverable"
    );
    f.stop();
    upstream.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_empty_lists_pin_empty_until_new_session() {
    let (mut f, upstream, a) = empty_fixture().await;
    let token = a["token"].as_str().unwrap();
    let session = wire::open(&f, token).await;
    let (one, two) = tokio::join!(list(&f, token, &session, 1), list(&f, token, &session, 2));
    for result in [one, two] {
        assert_eq!(result["result"]["tools"], json!([]));
    }
    grant(&f, a["public_id"].as_str().unwrap());
    assert_eq!(
        list(&f, token, &session, 3).await["result"]["tools"],
        json!([])
    );
    assert!(super::calls::call(&f, &a, &session, 4, json!({})).await["error"].is_object());
    assert!(super::calls::effects(&f).is_empty());
    let new = wire::open(&f, token).await;
    assert_eq!(
        list(&f, token, &new, 1).await["result"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    f.stop();
    upstream.stop();
}

async fn empty_fixture() -> (Fixture, receiver::Receiver, Value) {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let upstream = receiver::Receiver::start(&f);
    f.start(process::DAEMON).await;
    let a = f.enroll(
        "pin-empty",
        &format!("https://localhost:{}/mcp", upstream.port),
    );
    (f, upstream, a)
}
