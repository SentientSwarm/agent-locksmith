use super::{fixture::Fixture, flow, process, receiver};
use serde_json::{Value, json};
use std::{process::Stdio, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bearer_only_child_observes_trusted_https_without_inbound_tls() {
    let mut f = Fixture::new();
    configure(&f);
    let receiver = receiver::Receiver::start(&f);
    start(&mut f).await;
    let agent = f.enroll(
        "plain-observer",
        &format!("https://localhost:{}/mcp", receiver.port),
    );
    let id = agent["public_id"].as_str().unwrap();
    observe(&f, id);
    let counts: Value =
        serde_json::from_slice(&std::fs::read(f.path().join("counts.json")).unwrap()).unwrap();
    assert_eq!(counts["initialize"], 1);
    assert_eq!(counts["tools/list"], 1);
    assert_eq!(counts["tools/call"], Value::Null);
    f.stop();
    receiver.stop();
}

fn configure(f: &Fixture) {
    receiver::configure(f);
    let path = f.path().join("config.yaml");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["listen"]["auth_mode"] = "bearer".into();
    config["listen"].as_object_mut().unwrap().remove("mtls");
    assert!(config["listen"].get("admin_https").is_none());
    std::fs::write(path, config.to_string()).unwrap();
}

async fn start(f: &mut Fixture) {
    // exec starts a fresh process: the fixture parent's TLS provider cannot
    // initialize the daemon's outbound client on its behalf.
    let log = std::fs::File::create(f.path().join("daemon.log")).unwrap();
    let mut command = process::command(process::DAEMON);
    command.arg("--config").arg(f.path().join("config.yaml"));
    command
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    f.daemon = Some(process::Guard(command.spawn().unwrap()));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(f.daemon.as_mut().unwrap().0.try_wait().unwrap().is_none());
        if f.path().join("admin.sock").exists()
            && f.http
                .get(format!("http://127.0.0.1:{}/livez", f.port))
                .send()
                .await
                .is_ok_and(|response| response.status() == 200)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn observe(f: &Fixture, id: &str) {
    let current = flow::show(f, id);
    let file = flow::write(f, json!({"source":current["source"],"generation":null}));
    let result = process::run(f.command(&[
        "tool", "mcp", "observe", "native", "--agent", id, "--file", &file,
    ]));
    let log = std::fs::read_to_string(f.path().join("daemon.log")).unwrap();
    assert!(
        result.status.success(),
        "observation failed; provider panic={}",
        log.contains("No provider set")
    );
    let response: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(response["observation"]["status"], "ready");
    assert!(!log.contains("panicked"));
}
