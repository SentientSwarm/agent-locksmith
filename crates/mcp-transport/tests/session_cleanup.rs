mod session_support;
use locksmith_mcp_transport::sessions::Pool;
use rmcp::transport::{Transport, streamable_http_server::session::SessionManager};
use session_support::*;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn stalled_initialize_is_joined_and_capacity_recovers() {
    let pool = Pool::new(config()).unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let handler = Handler {
        stall_init: true,
        ..Default::default()
    };
    let (id, transport) = manager.create_session().await.unwrap();
    start(&manager, id.clone(), transport, handler.clone());
    assert!(manager.initialize_session(&id, init()).await.is_err());
    manager.wait_retired(&id).await;
    assert_eq!(handler.entered.load(Ordering::SeqCst), 1);
    assert_eq!(handler.live.load(Ordering::SeqCst), 0);
    assert_eq!(pool.snapshot().workers_joined, 1);
    assert_eq!(pool.snapshot().services_joined, 1);
    let _ = open(&scoped(&pool, "a", "x", "1"), Handler::default()).await;
    pool.shutdown().await;
}
#[tokio::test]
async fn canceled_close_cannot_drop_worker_join_custody() {
    let pool = Pool::new(config()).unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let (id, mut transport) = manager.create_session().await.unwrap();
    let m = manager.clone();
    let sid = id.clone();
    let init = tokio::spawn(async move { m.initialize_session(&sid, init()).await });
    assert!(
        transport.receive().await.is_some(),
        "SDK worker reached the stalled response wait"
    );
    let closing = tokio::spawn(async move { transport.close().await });
    until(|| pool.snapshot().closing == 1).await;
    closing.abort();
    let _ = closing.await;
    manager.wait_retired(&id).await;
    let _ = init.await;
    assert_eq!(pool.snapshot().workers_joined, 1);
    assert_eq!(pool.snapshot().released, 1);
}
#[tokio::test]
async fn worker_completion_alone_does_not_release_service_charge() {
    let pool = Pool::new(config()).unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let (id, transport) = manager.create_session().await.unwrap();
    let finish = tokio_util::sync::CancellationToken::new();
    let wait = finish.clone();
    manager.spawn_session(id.clone(), async move {
        wait.cancelled().await;
        true
    });
    drop(transport);
    until(|| pool.snapshot().workers_joined == 1).await;
    assert_eq!(pool.snapshot().entries, 1);
    assert_eq!(pool.snapshot().closing, 1);
    assert_eq!(pool.snapshot().released, 0);
    assert!(manager.create_session().await.is_err());
    finish.cancel();
    manager.wait_retired(&id).await;
    assert_eq!(pool.snapshot().services_joined, 1);
    assert_eq!(pool.snapshot().released, 1);
}
#[tokio::test]
async fn request_and_notification_futures_end_before_release() {
    let pool = Pool::new(config()).unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let handler = Handler::default();
    let id = open(&manager, handler.clone()).await;
    let stream = manager.create_stream(&id, message(serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stall"}}))).await.unwrap();
    manager.accept_message(&id, message(serde_json::json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"p","progress":1}}))).await.unwrap();
    until(|| handler.entered.load(Ordering::SeqCst) == 2).await;
    manager.retire(&id);
    drop(stream);
    manager.wait_retired(&id).await;
    assert_eq!(handler.live.load(Ordering::SeqCst), 0);
    assert_eq!(pool.snapshot().services_joined, 1);
    assert_eq!(pool.snapshot().workers_joined, 1);
}

#[tokio::test]
async fn finished_worker_and_service_keep_outstanding_response_charged() {
    let pool = Pool::new(config()).unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let id = open(&manager, Handler::default()).await;
    let stream = manager.create_standalone_stream(&id).await.unwrap();
    manager.retire(&id);
    until(|| pool.snapshot().workers_joined == 1 && pool.snapshot().services_joined == 1).await;
    assert_eq!(pool.snapshot().entries, 1);
    assert_eq!(pool.snapshot().released, 0);
    drop(stream);
    manager.wait_retired(&id).await;
    assert_eq!(pool.snapshot().released, 1);
}

#[tokio::test]
async fn transport_close_still_joins_after_pool_owner_is_dropped() {
    let pool = Pool::new(config()).unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let (_, mut transport) = manager.create_session().await.unwrap();
    drop(manager);
    drop(pool);
    tokio::time::timeout(std::time::Duration::from_secs(5), transport.close())
        .await
        .unwrap()
        .unwrap();
}
