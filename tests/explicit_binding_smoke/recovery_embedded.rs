//! Same assertions also run against the accepted pre-repair production library.
use super::{
    fixture::Fixture, oauth_setup as setup, process, recovery_common as common,
    recovery_provider::Provider, upstream,
};
use std::{path::Path, time::Duration};

pub async fn exercise(bootstrap: bool) {
    let receiver = upstream::Receiver::start().await;
    let provider = Provider::start().await;
    let mut f = Fixture::new(&receiver.server.uri());
    f.start_with_env(setup::ENV).await;
    let agent = setup::enroll_url(&f, &provider.url).await;
    if !bootstrap {
        common::connect(&f, "synthetic-initial");
    }
    f.stop();
    provider.hold();
    let mut child = spawn(&f);
    stage(&f, &mut child, "embedded-ready").await;
    if !bootstrap {
        common::expiry(&f, 1);
    }
    let request = common::attempt(&f, &agent.token, bootstrap);
    provider.arrived().await;
    std::fs::write(f.path().join("shutdown"), "stop").unwrap();
    stage(&f, &mut child, "returned").await;
    finish(f, provider, receiver, request, child).await;
}

async fn finish(
    mut f: Fixture,
    provider: Provider,
    receiver: upstream::Receiver,
    request: tokio::task::JoinHandle<()>,
    mut child: process::Guard,
) {
    let before = common::state(&f);
    f.start_with_env(setup::ENV).await; // Reacquire canonical state lock while embedding runtime lives.
    provider.release();
    request.await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        common::state(&f),
        before,
        "old refresh published after daemon return and ownership release"
    );
    assert_eq!(
        receiver.snapshot().await.1,
        0,
        "old proxy forwarded after daemon return"
    );
    std::fs::write(f.path().join("finish"), "stop").unwrap();
    worker_succeeded(&f, &mut child);
    f.cleanup();
    provider.stop().await;
}

/// The worker's exit, with its panic line on failure (AGENT-324).
fn worker_succeeded(f: &Fixture, child: &mut process::Guard) {
    if !process::wait(&mut child.0).success() {
        panic!("embedding worker failed: {}", worker_panic(f));
    }
}
/// Wait for a stage file the worker writes; if it never comes, say what
/// became of the worker rather than only that the stage timed out.
async fn stage(f: &Fixture, child: &mut process::Guard, name: &str) {
    let path = f.path().join(name);
    let reached = tokio::time::timeout(Duration::from_secs(12), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if reached.is_err() {
        let state = match child.0.try_wait().unwrap() {
            Some(status) => format!("exited {status}: {}", worker_panic(f)),
            None => "still running".into(),
        };
        panic!("embedded stage {name} not reached in 12s; worker {state}");
    }
}
/// The worker's output goes to a file in the fixture directory, never the
/// test's; only its panic location and message are shown.
fn worker_panic(f: &Fixture) -> String {
    let log = std::fs::read_to_string(f.path().join("worker.log")).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines
        .iter()
        .position(|l| l.contains("panicked at"))
        .map(|i| lines[i..lines.len().min(i + 2)].join(" | "))
        .unwrap_or_else(|| "no panic line".into())
}
fn spawn(f: &Fixture) -> process::Guard {
    spawn_entry(f, "embedded_oauth_recovery_worker", &[])
}
fn spawn_entry(f: &Fixture, entry: &str, env: &[(&str, &str)]) -> process::Guard {
    let mut c = process::command(std::env::current_exe().unwrap().to_str().unwrap());
    c.args(["--exact", entry, "--ignored", "--nocapture"])
        .envs(setup::ENV.iter().copied())
        .envs(env.iter().copied())
        .env("RECOVERY_EMBEDDED", f.path());
    let log = std::fs::File::create(f.path().join("worker.log")).unwrap();
    c.stdout(log.try_clone().unwrap()).stderr(log);
    process::Guard(c.spawn().unwrap())
}
async fn wait_path(path: &Path) {
    tokio::time::timeout(Duration::from_secs(12), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("embedded stage completed");
}

pub async fn worker() {
    let Some(dir) = std::env::var_os("RECOVERY_EMBEDDED") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let config = config(&dir);
    let port = config.listen.port;
    // Ready means this daemon's own admin socket exists and the port answers,
    // as for the fixture: a port alone could be another run's daemon
    // (fixed_port.rs), so the stale socket the stopped fixture left goes first.
    let socket = config.listen.admin_socket.as_ref().unwrap().path.clone();
    let _ = std::fs::remove_file(&socket);
    let coord = agent_locksmith::shutdown::ShutdownCoordinator::new(Duration::from_millis(10));
    let ready = dir.join("embedded-ready");
    let run = async {
        let result = agent_locksmith::daemon::run(config, coord.clone()).await;
        // Fail loudly, rather than leave the parent waiting on a daemon
        // that never came up (AGENT-324).
        if let Err(e) = &result {
            assert!(ready.exists(), "daemon returned before ready: {e}");
        }
        result
    };
    let control = async {
        let client = reqwest::Client::new();
        while !socket.exists()
            || client
                .get(format!("http://127.0.0.1:{port}/livez"))
                .send()
                .await
                .is_err()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        std::fs::write(&ready, "ready").unwrap();
        wait_path(&dir.join("shutdown")).await;
        coord.trigger();
    };
    let (result, ()) = tokio::join!(run, control);
    result.unwrap();
    std::fs::write(dir.join("returned"), "returned").unwrap();
    wait_path(&dir.join("finish")).await;
}

pub async fn startup_failure() {
    let receiver = upstream::Receiver::start().await;
    let provider = Provider::start().await;
    let mut f = Fixture::new(&receiver.server.uri());
    f.start_with_env(setup::ENV).await;
    setup::enroll_url(&f, &provider.url).await;
    common::connect(&f, "synthetic-startup");
    common::expiry(&f, 1);
    f.stop();
    provider.hold();
    let mut child = spawn_entry(
        &f,
        "oauth_startup_failure_worker",
        &[("LOCKSMITH_CREDENTIAL_SEALING_KEY", "synthetic-invalid-key")],
    );
    stage(&f, &mut child, "returned").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    no_startup_refresh(&provider);
    std::fs::write(f.path().join("finish"), "stop").unwrap();
    worker_succeeded(&f, &mut child);
    f.start_with_env(setup::ENV).await; // State lock released, no old worker remains.
    provider.arrived().await;
    provider.release();
    f.cleanup();
    provider.stop().await;
}

pub async fn startup_worker() {
    let Some(dir) = std::env::var_os("RECOVERY_EMBEDDED") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let config = config(&dir);
    let coord = agent_locksmith::shutdown::ShutdownCoordinator::new(Duration::from_millis(10));
    assert!(agent_locksmith::daemon::run(config, coord).await.is_err());
    std::fs::write(dir.join("returned"), "returned").unwrap();
    wait_path(&dir.join("finish")).await;
}

fn config(dir: &Path) -> agent_locksmith::config::AppConfig {
    agent_locksmith::config::parse_config_str(
        &std::fs::read_to_string(dir.join("config.yaml")).unwrap(),
    )
    .unwrap()
}

fn no_startup_refresh(provider: &Provider) {
    assert_eq!(
        provider.counts().0,
        1,
        "refresh survived startup-error return"
    );
}
