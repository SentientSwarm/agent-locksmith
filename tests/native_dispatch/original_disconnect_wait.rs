use locksmith_mcp_authority_proof::{Error, fixture::Fixture, wire::Wire};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn disconnect_while_waiting_for_admission_database_cannot_admit_or_dispatch() -> Result<(), Error> {
    let receiver = std::env::var("QA_RECEIVER")?;
    let f = Fixture::start(&receiver).await?;
    let w = Wire::open(&f, 0).await?;
    w.list(1).await?;
    let session = f.gateway.sessions.find(w.session.as_ref().unwrap(), &f.identities[0]).await?;
    f.core.prepared.enable();
    let request = w.clone();
    let wire = tokio::spawn(async move {
        request.request(reqwest::Method::POST).json(&json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"read","arguments":{"ticket":"db-wait"}}
        })).send().await
    });
    f.core.prepared.reached().await;
    let response = wire.await??;
    let pool = f.core.store.pool.clone();
    let mut connections = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        connections.push(pool.acquire().await?);
    }
    assert_eq!(pool.num_idle(), 0);
    assert!(!session.closed.is_cancelled());
    f.core.prepared.resume();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
        .fetch_one(&mut **connections.first_mut().unwrap()).await?;
    assert_eq!(before, 0);
    assert_eq!(f.core.slots.available_permits(), 7);
    drop(response);
    tokio::time::timeout(Duration::from_secs(2), session.closed.cancelled()).await?;
    drop(connections);
    tokio::time::timeout(Duration::from_secs(4), async {
        while f.core.slots.available_permits() != 8 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await?;
    let admitted: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
        .fetch_one(&pool).await?;
    let arrivals = f.arrivals()?;
    println!("QA_disconnect_during_database_wait: before_admissions={before} closed_before_pool_release=true after_admissions={admitted} tool_arrivals={arrivals}");
    f.finish().await?;
    assert_eq!(admitted, 0, "a session closed before the final database transaction must not be admitted");
    assert_eq!(arrivals, 0, "closed-before-admission request must not dispatch");
    Ok(())
}
