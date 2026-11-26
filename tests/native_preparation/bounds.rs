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
    refusals(&f, id);
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
/// Each upstream refusal reaches the operator as a fixed code (AGENT-369).
fn refusals(f: &Fixture, id: &str) {
    let challenge = "Bearer resource_metadata=\"https://localhost/.well-known\"";
    for (refuse, code) in [
        (
            json!({"status":401,"challenge":challenge}),
            "upstream_unauthorized",
        ),
        (json!({"status":403}), "upstream_forbidden"),
        (json!({"status":500,"body":true}), "upstream_status"),
        (json!({"status":200}), "upstream_observation_failed"),
    ] {
        std::fs::write(
            f.path().join("behavior.json"),
            json!({"refuse":refuse}).to_string(),
        )
        .unwrap();
        let s = flow::show(f, id);
        let file = f.path().join("refusal.json");
        std::fs::write(
            &file,
            json!({"source":s["source"],"generation":s["observation"]["generation"]}).to_string(),
        )
        .unwrap();
        let out = process::run(f.command(&[
            "tool",
            "mcp",
            "observe",
            "native",
            "--agent",
            id,
            "--file",
            file.to_str().unwrap(),
        ]));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{code}");
        assert!(stderr.contains(&format!("\"{code}\"")), "{code}: {stderr}");
        assert!(!stderr.contains("well-known"), "{code}: {stderr}");
    }
    // The operator learns which status and step refused, and nothing else (AGENT-371).
    let log = std::fs::read_to_string(f.path().join("daemon.log")).unwrap();
    let refused: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("native_upstream_refused"))
        .collect();
    assert!(
        refused
            .iter()
            .any(|l| l.contains("\"upstream_status\":500") && l.contains("\"step\":\"initialize\"")),
        "{refused:?}"
    );
    for line in refused {
        assert!(
            !line.contains("well-known") && !line.contains("jsonrpc"),
            "{line}"
        );
    }
}
