use super::support;
use crate::native_authority::{api, body_probe, body_scope};
use crate::oauth::refresh::RefreshOwner;
use axum::body::Body;
use serde_json::Value;
use std::{sync::Arc, time::Duration};

#[tokio::test(start_paused = true)]
async fn body_deadline_is_ten_seconds_and_size_stays_sixty_four_kib() {
    let owner = RefreshOwner::default();
    let key = "body-clock-ten".to_owned();
    let probe = body_probe::register(&key);
    let task = support::spawn(owner.clone(), key.clone());
    probe.entered().await;
    tokio::time::advance(Duration::from_millis(9999)).await;
    let still_pending = !task.is_finished();
    tokio::time::advance(Duration::from_millis(2)).await;
    let result = task.await.unwrap();
    owner.close();
    owner.wait().await;
    body_probe::remove(&key);
    let oversized =
        api::body::<Value>(support::request("unused", Body::from(vec![b' '; 65537]))).await;
    assert!(still_pending);
    assert_eq!(result.unwrap_err().0, "body_deadline");
    assert_eq!(oversized.unwrap_err().0, "body_limit");
}

#[tokio::test(start_paused = true)]
async fn body_time_does_not_consume_later_operation_clock() {
    let rt = Arc::new(support::runtime(RefreshOwner::default()));
    let (bytes, receive) = tokio::sync::mpsc::channel(1);
    let (operation, entered) = tokio::sync::oneshot::channel();
    let started = tokio::time::Instant::now();
    let task = operation_after_body(rt.clone(), receive, operation);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(9)).await;
    bytes
        .send(Ok(bytes::Bytes::from_static(b"null")))
        .await
        .unwrap();
    drop(bytes);
    entered.await.unwrap();
    tokio::time::advance(Duration::from_millis(9999)).await;
    let pending = !task.is_finished();
    tokio::time::advance(Duration::from_millis(2)).await;
    let result = task.await.unwrap();
    rt.owner.close();
    rt.owner.wait().await;
    assert!(pending);
    assert_eq!(result.unwrap_err().0, "operation_deadline");
    assert!(tokio::time::Instant::now() >= started + Duration::from_secs(19));
}
fn operation_after_body(
    rt: Arc<crate::native_authority::runtime::Runtime>,
    mut receive: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>,
    operation: tokio::sync::oneshot::Sender<()>,
) -> tokio::task::JoinHandle<crate::native_authority::Result<Value>> {
    tokio::spawn(async move {
        body_scope::run(&rt.owner, async {
            let stream = futures_util::stream::poll_fn(move |cx| receive.poll_recv(cx));
            api::body::<Value>(support::request("clock", Body::from_stream(stream))).await?;
            rt.scoped(async {
                operation.send(()).unwrap();
                std::future::pending().await
            })
            .await
        })
        .await
    })
}

#[tokio::test]
async fn stalled_bodies_do_not_reserve_any_of_eight_operation_slots() {
    let rt = support::runtime(RefreshOwner::default());
    let mut tasks = Vec::new();
    let mut probes = Vec::new();
    for n in 0..9 {
        let key = format!("body-not-slot-{n}");
        let p = body_probe::register(&key);
        tasks.push(support::spawn(rt.owner.clone(), key.clone()));
        probes.push((key, p));
    }
    for (_, p) in &probes {
        support::entered(p).await;
    }
    let available = rt.slots.available_permits();
    let permits = rt.slots.acquire_many(8).await.unwrap();
    let refused = rt.scoped(async { Ok(Value::Null) }).await.unwrap_err().0;
    drop(permits);
    let success = rt.scoped(async { Ok(Value::Null) }).await.is_ok();
    rt.owner.close();
    for task in tasks {
        support::join(task).await;
    }
    rt.owner.wait().await;
    for (key, _) in probes {
        body_probe::remove(&key);
    }
    assert_eq!(available, 8);
    assert_eq!(refused, "observation_capacity");
    assert!(success);
}
