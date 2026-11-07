use super::*;
pub(super) async fn run() {
    let mut f = fixture::Fixture::new();
    receiver::configure(&f);
    let up = receiver::Receiver::start(&f);
    config(&f, Some("finite-v2"));
    f.start(process::DAEMON).await;
    let a = f.enroll(
        "catalog-refusals",
        &format!("https://localhost:{}/mcp", up.port),
    );
    let id = a["public_id"].as_str().unwrap();
    write(&f, "manifest.json", tools());
    for pages in cases::pages() {
        write(&f, "pages.json", json!(pages));
        write(&f, "behavior.json", json!({"mode":"policy-pages"}));
        refuse(&f, id);
    }
    sse_refusals(&f, id);
    write(&f, "behavior.json", json!({}));
    grant_policy(&f, id);
    standard(&f, a["token"].as_str().unwrap()).await;
    f.stop();
    up.stop();
}
fn refuse(f: &fixture::Fixture, id: &str) {
    flow::refuse_observe(f, id);
    let state = flow::show(f, id);
    assert_eq!(state["observation"]["status"], "failed");
    assert_eq!(state["tools"], json!([]));
    assert_eq!(state["callable"], false);
    assert!(!f.path().join("effects.json").exists());
}
fn sse_refusals(f: &fixture::Fixture, id: &str) {
    for mode in ["policy-sse-notification", "policy-sse-held"] {
        write(f, "behavior.json", json!({"mode":mode}));
        flow::refuse_observe(f, id);
        assert_eq!(flow::show(f, id)["callable"], false);
        assert!(!f.path().join("effects.json").exists());
        if mode == "policy-sse-held" {
            assert!(f.path().join("held-sse-sent.json").exists());
            std::fs::write(f.path().join("release-policy-sse.json"), "true").unwrap();
        }
    }
}
