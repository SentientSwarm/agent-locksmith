mod session_support;
use locksmith_mcp_transport::sessions::{Error, Pool};
use rmcp::transport::streamable_http_server::session::SessionManager;
use session_support::*;

#[tokio::test]
async fn reservation_precedes_all_sdk_allocation() {
    let pool = Pool::new(config()).unwrap();
    let a = scoped(&pool, "a", "x", "1");
    let b = scoped(&pool, "a", "y", "1");
    let c = scoped(&pool, "b", "x", "1");
    let (_, first) = a.create_session().await.unwrap();
    let (_, second) = b.create_session().await.unwrap();
    let (_, third) = c.create_session().await.unwrap();
    for _ in 0..32 {
        assert!(matches!(a.create_session().await, Err(Error::Capacity)));
    }
    assert!(matches!(
        scoped(&pool, "a", "z", "1").create_session().await,
        Err(Error::Capacity)
    ));
    assert!(matches!(
        scoped(&pool, "c", "z", "1").create_session().await,
        Err(Error::Capacity)
    ));
    assert_eq!(pool.snapshot().workers_created, 3);
    drop((first, second, third));
    pool.shutdown().await;
    assert_eq!(pool.snapshot().workers_joined, 3);
    assert_eq!(pool.snapshot().released, 3);
}
#[tokio::test]
async fn wrong_owner_cannot_retire_victim_changed_authority_can() {
    let pool = Pool::new(config()).unwrap();
    let manager = scoped(&pool, "a", "x", "1");
    let id = open(&manager, Handler::default()).await;
    let attacker = scoped(&pool, "b", "x", "2");
    assert!(!attacker.has_session(&id).await.unwrap());
    attacker.close_session(&id).await.unwrap();
    assert!(manager.has_session(&id).await.unwrap());
    assert!(!scoped(&pool, "a", "x", "2").has_session(&id).await.unwrap());
    manager.wait_retired(&id).await;
    let replacement = scoped(&pool, "a", "x", "2");
    let new_id = open(&replacement, Handler::default()).await;
    assert_ne!(id, new_id);
    assert!(!replacement.has_session(&id).await.unwrap());
    pool.shutdown().await;
    assert_eq!(pool.snapshot().workers_joined, 2);
    assert_eq!(pool.snapshot().services_joined, 2);
}
#[tokio::test]
async fn concurrent_initializations_cannot_exceed_scope_budget() {
    let pool = Pool::new(config()).unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let m = scoped(&pool, "a", "x", "1");
        tasks.spawn(async move { m.create_session().await });
    }
    let mut transports = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok((_, transport)) = result.unwrap() {
            transports.push(transport);
        }
    }
    assert_eq!(transports.len(), 1);
    assert_eq!(pool.snapshot().workers_created, 1);
    drop(transports);
    pool.shutdown().await;
}
