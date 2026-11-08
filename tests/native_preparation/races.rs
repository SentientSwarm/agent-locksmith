use super::{fixture::Fixture, flow, process, receiver};
use serde_json::{Value, json};
use std::{process::Stdio, time::Duration};

async fn setup() -> (Fixture, receiver::Receiver, String) {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let receiver = receiver::Receiver::start(&f);
    f.start(process::DAEMON).await;
    let a = f.enroll("racer", &format!("https://localhost:{}/mcp", receiver.port));
    (f, receiver, a["public_id"].as_str().unwrap().to_owned())
}
fn behavior(f: &Fixture, value: Value) {
    let temp = f.path().join("behavior-next.json");
    std::fs::write(&temp, value.to_string()).unwrap();
    std::fs::rename(temp, f.path().join("behavior.json")).unwrap();
}
async fn held(f: &Fixture, id: &str, name: &str, mode: &str) -> process::Guard {
    behavior(f, json!({"hold":name,"mode":mode}));
    let s = flow::show(f, id);
    let file = flow::write(
        f,
        json!({"source":s["source"],"generation":s["observation"]["generation"]}),
    );
    let mut command = f.command(&[
        "tool", "mcp", "observe", "native", "--agent", id, "--file", &file,
    ]);
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let guard = process::Guard(command.spawn().unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !f.path().join(format!("arrived-{name}.json")).exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    guard
}
fn release(f: &Fixture, name: &str) {
    std::fs::write(f.path().join(format!("release-{name}.json")), b"true").unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_operation_deadline_leaves_no_later_publication() {
    let (mut f, receiver, id) = setup().await;
    let started = std::time::Instant::now();
    let mut old = held(&f, &id, "deadline", "good").await;
    assert!(!process::wait(&mut old.0).success());
    assert!(started.elapsed() < Duration::from_secs(15));
    let before = flow::show(&f, &id);
    assert_ne!(before["observation"]["status"], "ready");
    release(&f, "deadline");
    behavior(&f, json!({}));
    assert_eq!(flow::observe(&f, &id)["observation"]["status"], "ready");
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_old_success_and_old_failure_cannot_replace_new_success() {
    let (mut f, receiver, id) = setup().await;
    for (name, mode) in [("success", "good"), ("failure", "duplicate")] {
        let mut old = held(&f, &id, name, mode).await;
        behavior(&f, json!({}));
        let current = flow::observe(&f, &id);
        release(&f, name);
        assert!(!process::wait(&mut old.0).success());
        assert_eq!(flow::show(&f, &id), current);
    }
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_binding_aba_during_network_wait_refuses_publication() {
    let (mut f, receiver, id) = setup().await;
    let mut old = held(&f, &id, "aba", "good").await;
    f.op(&["agent", "unset-credential", &id, "native"]);
    f.op(&["agent", "set-credential", &id, "native", "--no-auth"]);
    release(&f, "aba");
    assert!(!process::wait(&mut old.0).success());
    let result = flow::show(&f, &id);
    assert_ne!(result["observation"]["status"], "ready");
    assert_eq!(result["tools"], json!([]));
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_shutdown_joins_held_observation_before_restart() {
    let (mut f, receiver, id) = setup().await;
    let mut old = held(&f, &id, "shutdown", "good").await;
    f.stop();
    assert!(!process::wait(&mut old.0).success());
    f.start(process::DAEMON).await;
    release(&f, "shutdown");
    let result = flow::show(&f, &id);
    assert_ne!(result["observation"]["status"], "ready");
    assert_eq!(result["observation"]["fresh"], false);
    behavior(&f, json!({}));
    assert_eq!(flow::observe(&f, &id)["observation"]["status"], "ready");
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_self_listener_is_refused_before_wire() {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let path = f.path().join("config.yaml");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["listen"]["port"] = 0.into();
    std::fs::write(path, config.to_string()).unwrap();
    f.port = 0;
    f.start(process::DAEMON).await;
    assert_ne!(f.port, 0);
    let a = f.enroll("self", &format!("https://localhost:{}/mcp/native", f.port));
    let id = a["public_id"].as_str().unwrap();
    let s = flow::show(&f, id);
    let file = flow::write(&f, json!({"source":s["source"],"generation":null}));
    let result = process::run(f.command(&[
        "tool", "mcp", "observe", "native", "--agent", id, "--file", &file,
    ]));
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("self_destination"));
    f.stop();
}
