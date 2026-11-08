mod session_support;
use futures_util::StreamExt;
use locksmith_mcp_transport::sessions::{Config, Error, Pool};
use rmcp::transport::streamable_http_server::session::SessionManager;
use session_support::*;
use std::time::Duration;

#[tokio::test]
async fn stream_and_message_budgets_precede_channel_growth() {
    let pool = Pool::new(Config {
        streams: 1,
        messages: 3,
        ..config()
    })
    .unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let id = open(&manager, Handler::default()).await;
    let mut stream = manager.create_stream(&id, ping(1)).await.unwrap();
    assert!(matches!(
        manager.create_stream(&id, ping(2)).await,
        Err(Error::Limit)
    ));
    while stream.next().await.is_some() {}
    drop(stream);
    let mut second = manager.create_stream(&id, ping(3)).await.unwrap();
    while second.next().await.is_some() {}
    drop(second);
    assert!(matches!(
        manager.create_stream(&id, ping(4)).await,
        Err(Error::Limit)
    ));
    pool.shutdown().await;
}
#[tokio::test]
async fn disconnect_retires_and_resume_is_unavailable() {
    let pool = Pool::new(config()).unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let id = open(&manager, Handler::default()).await;
    let stream = manager.create_standalone_stream(&id).await.unwrap();
    assert!(matches!(
        manager.create_standalone_stream(&id).await,
        Err(Error::Limit)
    ));
    assert!(matches!(
        manager.resume(&id, "0".into()).await,
        Err(Error::Resume)
    ));
    drop(stream);
    manager.wait_retired(&id).await;
    assert!(!manager.has_session(&id).await.unwrap());
}
#[tokio::test]
async fn lifetime_invalidation_and_restart_do_not_reuse_ids() {
    let pool = Pool::new(Config {
        lifetime: Duration::from_millis(100),
        ..config()
    })
    .unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let id = open(&manager, Handler::default()).await;
    manager.wait_retired(&id).await;
    assert_eq!(pool.snapshot().released, 1);
    let restarted = Pool::new(config()).unwrap();
    let next = scoped(&restarted, "a", "x", "1");
    assert!(!next.has_session(&id).await.unwrap());
    let replacement = open(&next, Handler::default()).await;
    restarted.invalidate("a", "x");
    next.wait_retired(&replacement).await;
    assert_eq!(restarted.snapshot().released, 1);
}
#[test]
fn invalid_or_unbounded_configuration_is_rejected() {
    assert!(
        Pool::<()>::new(Config {
            total: 0,
            ..config()
        })
        .is_err()
    );
    assert!(
        Pool::<()>::new(Config {
            lifetime: Duration::MAX,
            ..config()
        })
        .is_err()
    );
    assert!(
        Pool::<()>::new(Config {
            channel: 65,
            ..config()
        })
        .is_err()
    );
}

#[tokio::test]
async fn sdk_initialized_notification_ordering_remains_compatible() {
    let pool = Pool::new(Config {
        idle: Duration::from_millis(100),
        ..config()
    })
    .unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let (id, transport) = manager.create_session().await.unwrap();
    start(&manager, id.clone(), transport, Handler::default());
    manager.initialize_session(&id, init()).await.unwrap();
    let mut reply = manager.create_stream(&id, ping(1)).await.unwrap();
    assert!(reply.next().await.is_some());
    while reply.next().await.is_some() {}
    drop(reply);
    tokio::time::timeout(Duration::from_secs(5), manager.wait_retired(&id))
        .await
        .unwrap();
    assert_eq!(pool.snapshot().workers_joined, 1);
    assert_eq!(pool.snapshot().services_joined, 1);
}

#[tokio::test]
async fn malformed_handshakes_release_actual_workers() {
    let pool = Pool::new(config()).unwrap();
    for _ in 0..8 {
        let manager = scoped(&pool, "a", "x", "1");
        let (id, transport) = manager.create_session().await.unwrap();
        start(&manager, id.clone(), transport, Handler::default());
        let _ = manager.initialize_session(&id, ping(0)).await;
        manager.wait_retired(&id).await;
    }
    assert_eq!(pool.snapshot().workers_created, 8);
    assert_eq!(pool.snapshot().workers_joined, 8);
    assert_eq!(pool.snapshot().services_joined, 8);
    assert_eq!(pool.snapshot().entries, 0);
}

#[tokio::test]
async fn standalone_get_keeps_its_separate_request_budget() {
    let pool = Pool::new(Config {
        streams: 1,
        ..config()
    })
    .unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let id = open(&manager, Handler::default()).await;
    let get = manager.create_standalone_stream(&id).await.unwrap();
    let mut response = manager.create_stream(&id, ping(1)).await.unwrap();
    assert!(matches!(
        manager.create_stream(&id, ping(2)).await,
        Err(Error::Limit)
    ));
    while response.next().await.is_some() {}
    drop(response);
    drop(get);
    manager.wait_retired(&id).await;
    assert_eq!(pool.snapshot().released, 1);
}
