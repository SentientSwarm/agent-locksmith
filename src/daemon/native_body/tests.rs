#[path = "fixture.rs"]
mod fixture;
use fixture::Fixture;
use std::{sync::atomic::Ordering::SeqCst, time::Duration};

const DRAIN: Duration = Duration::from_secs(2);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uds_all_three_write_bodies_drop_before_forced_daemon_return() {
    for (method, path) in routes() {
        journey(false, method, path).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verified_https_all_three_write_bodies_drop_before_forced_daemon_return() {
    for (method, path) in routes() {
        journey(true, method, path).await;
    }
}
fn routes() -> [(&'static str, &'static str); 3] {
    [
        (
            "POST",
            "/admin/operator/tools/fixture/mcp/observations/subject",
        ),
        ("PUT", "/admin/operator/tools/fixture/mcp/reviews/subject"),
        ("PUT", "/admin/operator/agents/subject/mcp-grants/fixture"),
    ]
}
async fn journey(tls: bool, method: &str, path: &str) {
    let mut f = Fixture::new(tls);
    let config = f.config.take().expect("fixture config consumed once");
    // The held listener never completes, so the drain always times out; the
    // window only has to outlast the listener reaching its hold. With 1 ms a
    // slow runner aborted the listener before the hold and `forced` stayed 0.
    let (coord, mut daemon) = super::run_with_drain_window(config, DRAIN).await;
    let ready = f.ready().await;
    let (mut client, bytes) = f.request(path, method);
    let _ = bytes.send(Ok(bytes::Bytes::from_static(b"{"))).await;
    let entered = tokio::time::timeout(Duration::from_secs(3), f.probe.entered())
        .await
        .is_ok();
    coord.trigger();
    let (normal_return, dropped_at_return, forced, aborted) = finish(&mut daemon, &f).await;
    let lock = super::state_lock::acquire(Some(&f.dir.path().join("state.db")));
    let lock_reacquired = lock.is_ok();
    client.abort();
    let _ = (&mut client).await;
    drop(bytes);
    drop(lock);
    assert!(ready && entered && normal_return && lock_reacquired);
    assert_eq!(dropped_at_return, 1, "body lifetime, before client cleanup");
    assert_eq!(
        forced, 1,
        "test held actual listener completion to force drain"
    );
    assert_eq!(aborted, 1, "held listener future dropped by forced cleanup");
}

async fn finish(
    daemon: &mut tokio::task::JoinHandle<Result<(), super::DaemonError>>,
    f: &Fixture,
) -> (bool, usize, usize, usize) {
    let completed = tokio::time::timeout(Duration::from_secs(20), &mut *daemon).await;
    let normal_return = matches!(completed, Ok(Ok(Ok(()))));
    let dropped_at_return = f.probe.dropped.load(SeqCst);
    let forced = f.held.forced.load(SeqCst);
    let aborted = f.held.aborted.load(SeqCst);
    if !daemon.is_finished() {
        daemon.abort();
        let _ = (&mut *daemon).await;
    }
    (normal_return, dropped_at_return, forced, aborted)
}
