//! Actual killed child processes at production custody boundaries; provider
//! lives in the parent, preserving one-use consumption across child restarts.
mod fixture;
mod provider;
use fixture::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_death_never_replays_uncertain_pair() {
    for point in ["claimed", "consumed", "decoded", "committed"] {
        exercise(point).await;
    }
}

async fn exercise(point: &str) {
    let f = Fixture::new().await;
    let provider = provider::Provider::new(point == "consumed").await;
    let mut child = f.spawn(point, &provider.url);
    f.observed(point, &provider).await;
    child.0.kill().unwrap(); // SIGKILL on Unix; wait before same-state reopen.
    assert!(!child.0.wait().unwrap().success());
    provider.release.notify_one();
    f.assert_state(point).await;
    assert!(
        f.spawn("restart", &provider.url)
            .0
            .wait()
            .unwrap()
            .success()
    );
    let expected = usize::from(point != "claimed");
    assert_eq!(provider.arrivals(), expected);
    assert_eq!(provider.consumed(), expected);
    assert_eq!(
        provider.issued(),
        usize::from(matches!(point, "decoded" | "committed"))
    );
    println!("SIGKILL/reap/{point}: arrivals={expected}, no replay; same DB/WAL retained");
    provider.stop().await;
}

#[tokio::test]
#[ignore = "subprocess worker; parent supplies isolated synthetic state"]
async fn worker() {
    if std::env::var_os("OAUTH_RECOVERY_DB").is_none() {
        return;
    }
    fixture::worker().await;
}
