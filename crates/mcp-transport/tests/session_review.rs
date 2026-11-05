mod session_support;
use locksmith_mcp_transport::sessions::{Config, Pool};
use rmcp::transport::streamable_http_server::session::SessionManager;
use session_support::*;
use std::time::Duration;

#[tokio::test]
async fn absolute_lifetime_bounds_stalled_initialization() {
    let pool = Pool::new(Config {
        handshake: Duration::from_secs(3),
        lifetime: Duration::from_millis(120),
        ..config()
    })
    .unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let handler = Handler {
        stall_init: true,
        ..Default::default()
    };
    let (id, transport) = manager.create_session().await.unwrap();
    start(&manager, id.clone(), transport, handler.clone());
    let m = manager.clone();
    let sid = id.clone();
    let initializing = tokio::spawn(async move { m.initialize_session(&sid, init()).await });
    until(|| handler.entered.load(std::sync::atomic::Ordering::SeqCst) == 1).await;
    tokio::time::timeout(Duration::from_secs(1), manager.wait_retired(&id))
        .await
        .expect("absolute lifetime must include stalled initialization");
    assert!(initializing.await.unwrap().is_err());
    assert_eq!(handler.live.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(pool.snapshot().workers_joined, 1);
    assert_eq!(pool.snapshot().services_joined, 1);
}
