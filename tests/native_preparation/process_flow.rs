use super::{fixture::Fixture, process, receiver, wire};
use serde_json::{Value, json};
use std::{io::Write, process::Stdio};

pub async fn journey() {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let receiver = receiver::Receiver::start(&f);
    f.start_with_key(
        process::DAEMON,
        Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
    )
    .await;
    let agent = f.enroll(
        "observer",
        &format!("https://localhost:{}/mcp", receiver.port),
    );
    let id = agent["public_id"].as_str().unwrap();
    prepared(&f, id);
    deny(&f, agent["token"].as_str().unwrap()).await;
    let before = show(&f, id);
    replace(&f, id, &before, json!([]));
    ingest(&f, id);
    assert_eq!(observe(&f, id)["observation"]["status"], "ready");
    rejected_responses(&f, id);
    f.stop();
    receiver.stop();
    assert!(
        !std::fs::read_to_string(f.path().join("daemon.log"))
            .unwrap()
            .contains("synthetic-quoted")
    );
}
fn prepared(f: &Fixture, id: &str) {
    let first = observe(f, id);
    assert_eq!(first["observation"]["status"], "ready");
    let reviewed = review(f, id, &first);
    replace(
        f,
        id,
        &first,
        json!([{"name":"read_record","contract_digest":reviewed["contract_digest"]}]),
    );
}
fn rejected_responses(f: &Fixture, id: &str) {
    for mode in ["duplicate", "echo"] {
        std::fs::write(
            f.path().join("behavior.json"),
            json!({"mode":mode}).to_string(),
        )
        .unwrap();
        refuse_observe(f, id);
        assert_eq!(show(f, id)["observation"]["status"], "failed");
    }
    let counts: Value =
        serde_json::from_slice(&std::fs::read(f.path().join("counts.json")).unwrap()).unwrap();
    assert_eq!(counts["tools/call"], Value::Null);
}
pub fn show(f: &Fixture, id: &str) -> Value {
    f.op(&["tool", "mcp", "show", "native", "--agent", id])
}
pub fn write(f: &Fixture, body: Value) -> String {
    let path = f.path().join("request.json");
    std::fs::write(&path, body.to_string()).unwrap();
    path.to_str().unwrap().into()
}
pub fn observe(f: &Fixture, id: &str) -> Value {
    let s = show(f, id);
    let file = write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"]}),
    );
    f.op(&[
        "tool", "mcp", "observe", "native", "--agent", id, "--file", &file,
    ])
}
pub fn refuse_observe(f: &Fixture, id: &str) {
    let s = show(f, id);
    let file = write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"]}),
    );
    assert!(
        !process::run(f.command(&[
            "tool", "mcp", "observe", "native", "--agent", id, "--file", &file
        ]))
        .status
        .success()
    );
}
fn review(f: &Fixture, id: &str, s: &Value) -> Value {
    let file = write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"],"name":"read_record",
        "observed_digest":s["observation"]["manifest"]["tools"][0]["observed_digest"],"effect":"read"}),
    );
    f.op(&[
        "tool", "mcp", "review", "native", "--agent", id, "--file", &file,
    ])
}
fn replace(f: &Fixture, id: &str, s: &Value, tools: Value) {
    let file = write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"],"revision":s["grant_revision"],"tools":tools}),
    );
    let out = f.op(&[
        "agent",
        "mcp-grants",
        "replace",
        "native",
        "--agent",
        id,
        "--file",
        &file,
    ]);
    assert_eq!(out["callable"], false);
}
fn ingest(f: &Fixture, id: &str) {
    let mut cmd = f.command(&[
        "agent",
        "set-credential",
        id,
        "native",
        "--stored-bearer-stdin",
    ]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = process::Guard(cmd.spawn().unwrap());
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"synthetic-quoted\"value\\end\n")
        .unwrap();
    assert!(process::wait(&mut child.0).success());
}
async fn deny(f: &Fixture, token: &str) {
    let session = wire::open(f, token).await;
    let result = wire::post(
        f,
        token,
        Some(&session),
        json!({"jsonrpc":"2.0","id":100,"method":"tools/list"}),
    )
    .await
    .text()
    .await
    .unwrap();
    assert!(result.contains("\"tools\":[]"));
    let result=wire::post(f,token,Some(&session),json!({"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"read_record","arguments":{}}})).await.text().await.unwrap();
    assert!(result.contains("tool_not_approved"));
}
