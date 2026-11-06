use super::support;
use crate::native_authority::{api, body_probe, body_scope};
use crate::oauth::refresh::RefreshOwner;
use axum::body::Body;
use serde_json::{Value, json};
use std::{
    sync::{Arc, atomic::Ordering::SeqCst},
    time::Duration,
};

#[tokio::test]
async fn normal_body_completion_releases_scope() {
    let owner = RefreshOwner::default();
    let result = body_scope::run(
        &owner,
        api::body::<Value>(support::request(
            "normal-complete",
            Body::from("{\"ok\":true}"),
        )),
    )
    .await;
    owner.close();
    let joined = tokio::time::timeout(Duration::from_secs(1), owner.wait())
        .await
        .is_ok();
    assert!(joined);
    assert_eq!(result.unwrap(), json!({"ok":true}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_racing_body_registration_drops_all_admitted_bodies() {
    let owner = RefreshOwner::default();
    let barrier = Arc::new(tokio::sync::Barrier::new(17));
    let mut rows = Vec::new();
    for n in 0..16 {
        let key = format!("body-register-race-{n}");
        let probe = body_probe::register(&key);
        rows.push((
            key.clone(),
            probe,
            contend(owner.clone(), barrier.clone(), key),
        ));
    }
    barrier.wait().await;
    owner.close();
    let waited = tokio::time::timeout(Duration::from_secs(1), owner.wait())
        .await
        .is_ok();
    let closed = released(rows).await;
    assert!(waited && closed);
}
fn contend(
    owner: RefreshOwner,
    barrier: Arc<tokio::sync::Barrier>,
    key: String,
) -> tokio::task::JoinHandle<crate::native_authority::Result<Value>> {
    tokio::spawn(async move {
        barrier.wait().await;
        body_scope::run(
            &owner,
            api::body::<Value>(support::request(&key, support::pending_body())),
        )
        .await
    })
}

async fn released(
    rows: Vec<(
        String,
        Arc<body_probe::Probe>,
        tokio::task::JoinHandle<crate::native_authority::Result<Value>>,
    )>,
) -> bool {
    let mut closed = true;
    for (key, probe, mut task) in rows {
        let result = tokio::time::timeout(Duration::from_secs(1), &mut task).await;
        closed &= matches!(
            result,
            Ok(Ok(Err(crate::native_authority::Error("shutting_down"))))
        );
        if !task.is_finished() {
            task.abort();
            let _ = task.await;
        }
        closed &= probe.entered.load(SeqCst) == probe.dropped.load(SeqCst);
        body_probe::remove(&key);
    }
    closed
}
