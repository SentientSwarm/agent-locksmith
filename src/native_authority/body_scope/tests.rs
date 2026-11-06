#[path = "clocks.rs"]
mod clocks;
#[path = "races.rs"]
mod races;
#[path = "support.rs"]
mod support;
use super::super::{Error, body_probe};
use crate::oauth::refresh::RefreshOwner;
use serde_json::Value;
use std::{
    sync::atomic::{AtomicBool, Ordering::SeqCst},
    time::Duration,
};

#[tokio::test]
async fn body_drop_precedes_owner_wait_and_canonical_lock_release() {
    let owner = RefreshOwner::default();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let key = path.to_string_lossy().into_owned();
    let probe = body_probe::register(&key);
    let lock = crate::daemon::body_test_lock(&path).unwrap();
    let task = support::spawn(owner.clone(), key.clone());
    support::entered(&probe).await;
    owner.close();
    let waited = tokio::time::timeout(Duration::from_secs(1), owner.wait())
        .await
        .is_ok();
    let dropped_before_release = probe.dropped.load(SeqCst) == 1;
    drop(lock);
    let reacquired = crate::daemon::body_test_lock(&path);
    let canonical_reacquired = reacquired.is_ok();
    tokio::task::yield_now().await; // SAME embedding runtime remains alive.
    let dropped_before_cleanup = probe.dropped.load(SeqCst) == 1;
    support::join(task).await;
    drop(reacquired);
    body_probe::remove(&key);
    witness(
        waited,
        dropped_before_release,
        dropped_before_cleanup,
        canonical_reacquired,
    );
    assert!(waited && dropped_before_release && dropped_before_cleanup);
}

#[tokio::test]
async fn already_closed_owner_never_polls_body_or_operation() {
    let owner = RefreshOwner::default();
    owner.close();
    let polled = AtomicBool::new(false);
    let result = super::run(&owner, async {
        polled.store(true, SeqCst);
        Ok(Value::Null)
    })
    .await;
    assert_eq!(result.unwrap_err().0, "shutting_down");
    assert!(!polled.load(SeqCst));
}

#[tokio::test]
async fn caller_abort_drops_body_before_wait_and_nested_close_never_self_waits() {
    let owner = RefreshOwner::default();
    let key = "body-caller-abort".to_owned();
    let probe = body_probe::register(&key);
    let task = support::spawn(owner.clone(), key.clone());
    support::entered(&probe).await;
    support::join(task).await;
    owner.close();
    let waited = tokio::time::timeout(Duration::from_secs(1), owner.wait())
        .await
        .is_ok();
    let dropped = probe.dropped.load(SeqCst);
    body_probe::remove(&key);
    assert!(waited);
    assert_eq!(dropped, 1);
}

#[tokio::test]
async fn nested_registration_cancels_and_drops_without_waiting_inside_scope() {
    let owner = RefreshOwner::default();
    let rt = std::sync::Arc::new(support::runtime(owner.clone()));
    let (entered, signal) = tokio::sync::oneshot::channel();
    let mut task = tokio::spawn(async move {
        super::run(
            &rt.owner,
            rt.scoped(async {
                entered.send(()).unwrap();
                std::future::pending::<Result<Value, Error>>().await
            }),
        )
        .await
    });
    signal.await.unwrap();
    owner.close();
    let waited = tokio::time::timeout(Duration::from_secs(1), owner.wait())
        .await
        .is_ok();
    let result = tokio::time::timeout(Duration::from_secs(1), &mut task).await;
    if result.is_err() {
        task.abort();
        let _ = task.await;
    }
    assert!(waited);
    assert_eq!(result.unwrap().unwrap().unwrap_err().0, "shutting_down");
}

fn witness(
    waited: bool,
    dropped_before_release: bool,
    dropped_before_cleanup: bool,
    canonical_reacquired: bool,
) {
    eprintln!(
        "N206_BODY_OWNER_WITNESS {}",
        serde_json::json!({
            "waited": waited,
            "dropped_before_release": dropped_before_release,
            "dropped_before_cleanup": dropped_before_cleanup,
            "canonical_reacquired": canonical_reacquired,
        })
    );
    assert!(canonical_reacquired);
}
