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
    let child = spawn(&f);
    wait_path(&f.path().join("embedded-ready")).await;
    if !bootstrap {
        common::expiry(&f, 1);
    }
    let request = common::attempt(&f, &agent.token, bootstrap);
    provider.arrived().await;
    std::fs::write(f.path().join("shutdown"), "stop").unwrap();
    wait_path(&f.path().join("returned")).await;
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
    assert!(process::wait(&mut child.0).success());
    f.cleanup();
    provider.stop().await;
}

fn spawn(f: &Fixture) -> process::Guard {
    spawn_entry(f, "embedded_oauth_recovery_worker", &[])
}
fn spawn_entry(f: &Fixture, entry: &str, env: &[(&str, &str)]) -> process::Guard {
    let mut c = process::command(std::env::current_exe().unwrap().to_str().unwrap());
    c.args(["--exact", entry, "--ignored", "--nocapture"])
        .envs(setup::ENV.iter().copied())
        .envs(env.iter().copied())
        .env("RECOVERY_EMBEDDED", f.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
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
    let coord = agent_locksmith::shutdown::ShutdownCoordinator::new(Duration::from_millis(10));
    let run = agent_locksmith::daemon::run(config, coord.clone());
    let control = async {
        let client = reqwest::Client::new();
        while client
            .get(format!("http://127.0.0.1:{port}/livez"))
            .send()
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        std::fs::write(dir.join("embedded-ready"), "ready").unwrap();
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
    wait_path(&f.path().join("returned")).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    no_startup_refresh(&provider);
    std::fs::write(f.path().join("finish"), "stop").unwrap();
    assert!(process::wait(&mut child.0).success());
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
