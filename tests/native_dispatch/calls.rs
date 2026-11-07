use super::{discovery, fixture::Fixture, process, receiver, wire};
use serde_json::{Value, json};
use std::{io::Write, process::Stdio};

pub fn stored(f: &Fixture, id: &str, value: &str) -> String {
    let mut cmd = f.command(&[
        "agent",
        "set-credential",
        id,
        "native",
        "--stored-bearer-stdin",
    ]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = process::Guard(cmd.spawn().unwrap());
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(value.as_bytes())
        .unwrap();
    assert!(process::wait(&mut child.0).success());
    let value = f.op(&["agent", "credentials", "list", id]);
    value[0]["auth_spec"]["secret_ref"].as_str().unwrap().into()
}
pub async fn call(f: &Fixture, a: &Value, session: &str, id: u64, args: Value) -> Value {
    let r = wire::post(f,a["token"].as_str().unwrap(),Some(session),
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"read_record","arguments":args}})).await;
    let text = r.text().await.unwrap();
    serde_json::from_str(
        text.lines()
            .find_map(|l| l.strip_prefix("data: "))
            .unwrap_or(&text),
    )
    .unwrap()
}
pub fn effects(f: &Fixture) -> Vec<Value> {
    std::fs::read(f.path().join("effects.json"))
        .map(|v| serde_json::from_slice(&v).unwrap())
        .unwrap_or_default()
}
async fn success(f: &Fixture, a: &Value, account: &str) -> String {
    discovery::grant(f, a["public_id"].as_str().unwrap());
    let session = wire::open(f, a["token"].as_str().unwrap()).await;
    assert_eq!(
        discovery::list(f, a["token"].as_str().unwrap(), &session, 1).await["result"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let result = call(f, a, &session, 2, json!({"key":"safe-record"})).await;
    assert_eq!(
        result["result"]["structuredContent"]["account"], account,
        "{result}"
    );
    session
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_daemon_dispatches_x_x_y_and_none_after_committed_audit() {
    let (mut f, receiver, agents) = accounts().await;
    for (a, account) in agents.iter().zip(["X", "X", "Y", "None"]) {
        success(&f, a, account).await;
    }
    received(&f);
    super::results::negatives(&f, &agents[0]).await;
    f.stop();
    receiver.stop();
}

fn received(f: &Fixture) {
    let received = effects(f);
    assert_eq!(
        received
            .iter()
            .map(|v| v["account"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["X", "X", "Y", "None"]
    );
    assert_eq!(
        received
            .iter()
            .map(|v| v["committed"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
}

async fn accounts() -> (Fixture, receiver::Receiver, Vec<Value>) {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let receiver = receiver::Receiver::start(&f);
    f.start_with_key(
        process::DAEMON,
        Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
    )
    .await;
    let url = format!("https://localhost:{}/mcp", receiver.port);
    let agents: Vec<_> = ["one", "two", "three", "anonymous"]
        .iter()
        .map(|n| f.enroll(n, &url))
        .collect();
    select(&f, &agents);
    (f, receiver, agents)
}

fn select(f: &Fixture, agents: &[Value]) {
    let x = stored(
        f,
        agents[0]["public_id"].as_str().unwrap(),
        "fixture-account-x",
    );
    f.op(&[
        "agent",
        "set-credential",
        agents[1]["public_id"].as_str().unwrap(),
        "native",
        "--stored-bearer-ref",
        &x,
    ]);
    stored(
        f,
        agents[2]["public_id"].as_str().unwrap(),
        "fixture-account-y",
    );
}
