use super::support as s;
use serde_json::json;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checked_success_survives_cleanup_deadline() {
    let (mut f, receiver, a) = s::setup().await;
    let id = a["public_id"].as_str().unwrap();
    let r = s::review(&f, id, json!({"workspace":"fixed"}), "read_record");
    s::grant(&f, id, &r);
    let session = s::open(&f, &a).await;
    f.http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .add_root_certificate(reqwest::Certificate::from_pem(f.pki.ca.as_bytes()).unwrap())
        .build()
        .unwrap();
    s::behavior(&f, json!({"cleanup_hold":"cleanup"}));
    let result = s::call(&f, &a, &session, 2, json!({"key":"read"})).await;
    assert_eq!(result["result"]["content"][0]["text"], "None", "{result}");
    assert!(f.path().join("arrived-cleanup.json").exists());
    assert_eq!(s::effects(&f).len(), 1);
    assert_eq!(s::audit(&f, "mcp_admitted").await.len(), 1);
    assert!(s::audit(&f, "mcp_outcome").await.is_empty());
    let log = std::fs::read_to_string(f.path().join("daemon.log")).unwrap();
    assert!(
        log.contains("native_diagnostic_unavailable")
            || log.contains("native_operation_interrupted")
    );
    assert!(!log.contains("synthetic diagnostic failure"));
    std::fs::write(f.path().join("release-cleanup.json"), "true").unwrap();
    f.stop();
    receiver.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checked_tool_error_has_correlated_nonsecret_terminal_evidence() {
    let (mut f, receiver, a) = s::setup().await;
    let id = a["public_id"].as_str().unwrap();
    let r = s::review(&f, id, json!({"workspace":"context-canary"}), "read_record");
    s::grant(&f, id, &r);
    let session = s::open(&f, &a).await;
    s::behavior(&f, json!({"tool_error":true}));
    assert_eq!(
        s::call(&f, &a, &session, 2, json!({"key":"argument-canary"})).await["result"]["isError"],
        true
    );
    let admitted = s::audit(&f, "mcp_admitted").await;
    let outcomes = s::audit(&f, "mcp_outcome").await;
    assert_eq!(admitted.len(), 1);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0]["phase"], "completed");
    assert_eq!(outcomes[0]["outcome"], "tool_error");
    assert_eq!(outcomes[0]["operation_id"], admitted[0]["operation_id"]);
    for text in [
        serde_json::to_string(&outcomes).unwrap(),
        std::fs::read_to_string(f.path().join("daemon.log")).unwrap(),
    ] {
        assert!(!text.contains("context-canary"));
        assert!(!text.contains("argument-canary"));
    }
    assert_eq!(s::effects(&f).len(), 1);
    f.stop();
    receiver.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checked_success_survives_actual_terminal_database_refusal() {
    let (mut f, receiver, a) = s::setup().await;
    let id = a["public_id"].as_str().unwrap();
    let r = s::review(&f, id, json!({"workspace":"fixed"}), "read_record");
    s::grant(&f, id, &r);
    let session = s::open(&f, &a).await;
    s::behavior(&f, json!({"outcome_fail":true}));
    let start = std::time::Instant::now();
    let result = s::call(&f, &a, &session, 2, json!({"key":"read"})).await;
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(result["result"]["content"][0]["text"], "None", "{result}");
    assert_eq!(s::effects(&f).len(), 1);
    assert_eq!(s::audit(&f, "mcp_admitted").await.len(), 1);
    assert!(s::audit(&f, "mcp_outcome").await.is_empty());
    let log = std::fs::read_to_string(f.path().join("daemon.log")).unwrap();
    assert!(log.contains("native_diagnostic_unavailable"));
    assert!(!log.contains("synthetic diagnostic failure"));
    f.stop();
    receiver.stop();
}
