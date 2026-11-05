use super::{
    calls::{call, effects},
    discovery,
    fixture::Fixture,
    flow, wire,
};
use serde_json::{Value, json};

pub async fn negatives(f: &Fixture, a: &Value) {
    let token = a["token"].as_str().unwrap();
    let session = wire::open(f, token).await;
    assert!(call(f, a, &session, 1, json!({})).await["error"].is_object());
    assert_eq!(effects(f).len(), 4);
    discovery::list(f, token, &session, 2).await;
    assert!(
        call(f, a, &session, 3, json!({"unknown":"canary-argument"})).await["error"].is_object()
    );
    assert_eq!(effects(f).len(), 4);
    result_failures(f, a, &session).await;
    let log = std::fs::read_to_string(f.path().join("daemon.log")).unwrap();
    assert!(!log.contains("fixture-account-x") && !log.contains("canary-argument"));
    revoke(f, a);
    assert!(call(f, a, &session, 30, json!({})).await["error"].is_object());
    assert_eq!(effects(f).len(), 4 + MODES.len());
}

fn revoke(f: &Fixture, a: &Value) {
    let s = flow::show(f, a["public_id"].as_str().unwrap());
    let file = flow::write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"],"revision":s["grant_revision"],"tools":[]}),
    );
    f.op(&[
        "agent",
        "mcp-grants",
        "replace",
        "native",
        "--agent",
        a["public_id"].as_str().unwrap(),
        "--file",
        &file,
    ]);
}

const MODES: [&str; 12] = [
    "tool-error",
    "bad-output",
    "resource",
    "echo",
    "oversize",
    "wrong-id",
    "escaped-text",
    "escaped-key",
    "structured-echo",
    "rpc-error",
    "duplicate-json",
    "duplicate-sse",
];

async fn result_failures(f: &Fixture, a: &Value, session: &str) {
    for (i, mode) in MODES.into_iter().enumerate() {
        std::fs::write(
            f.path().join("behavior.json"),
            json!({"call_mode":mode}).to_string(),
        )
        .unwrap();
        let r = call(f, a, session, 10 + i as u64, json!({})).await;
        if mode == "tool-error" {
            assert_eq!(r["result"]["isError"], true);
        } else {
            assert_eq!(r["error"]["data"]["code"], "tool_outcome_unknown", "{r}");
        }
        assert_eq!(effects(f).len(), 5 + i, "exactly one arrival, never replay");
    }
}
