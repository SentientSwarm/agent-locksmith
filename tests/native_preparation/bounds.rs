use super::{fixture::Fixture, flow, process, receiver};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_sse_success_and_incomplete_manifests_never_publish() {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let r = receiver::Receiver::start(&f);
    f.start(process::DAEMON).await;
    let agent = f.enroll("bounds", &format!("https://localhost:{}/mcp", r.port));
    let id = agent["public_id"].as_str().unwrap();
    behavior(&f, "sse");
    assert_eq!(flow::observe(&f, id)["observation"]["status"], "ready");
    invalid(&f, id);
    f.stop();
    r.stop();
}
fn invalid(f: &Fixture, id: &str) {
    for mode in [
        "metadata",
        "schema",
        "wrong-id",
        "oversize",
        "too-many",
        "pages",
        "duplicate-names",
        "cursor",
    ] {
        behavior(f, mode);
        flow::refuse_observe(f, id);
        assert_eq!(
            flow::show(f, id)["observation"]["status"],
            "failed",
            "{mode}"
        );
    }
    let counts: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.path().join("counts.json")).unwrap()).unwrap();
    assert_eq!(counts["tools/call"], serde_json::Value::Null);
}
fn behavior(f: &Fixture, mode: &str) {
    std::fs::write(
        f.path().join("behavior.json"),
        json!({"mode":mode}).to_string(),
    )
    .unwrap();
}
