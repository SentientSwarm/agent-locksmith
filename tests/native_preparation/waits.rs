use super::support::{Setup, tool};
use agent_locksmith::native_authority::writes;
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn final_review_and_grant_recheck_source_after_pool_wait() {
    for review in [false, true] {
        let s = Arc::new(Setup::new().await);
        let first = s.publish(vec![tool("one")]).await;
        let entry = s.review(&first, "one").await;
        let mut held = Vec::new();
        for _ in 0..s.f.pool.options().get_max_connections() {
            held.push(s.f.pool.acquire().await.unwrap());
        }
        let task = pending(s.clone(), first, entry, review);
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        sqlx::query(
            "DELETE FROM agent_credential_overrides WHERE agent_id=? AND registration='native'",
        )
        .bind(s.f.agent_id)
        .execute(&mut **held.last_mut().unwrap())
        .await
        .unwrap();
        drop(held);
        assert!(task.await.unwrap().is_err());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM native_tool_grants")
            .fetch_one(&s.f.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
fn pending(
    s: Arc<Setup>,
    first: serde_json::Value,
    entry: serde_json::Value,
    review: bool,
) -> tokio::task::JoinHandle<agent_locksmith::native_authority::Result<serde_json::Value>> {
    tokio::spawn(async move {
        if review {
            let input: writes::Review = serde_json::from_value(json!({"source":first["source"],"generation":first["observation"]["generation"],"name":"one","observed_digest":first["observation"]["manifest"]["tools"][0]["observed_digest"],"effect":"write"})).unwrap();
            s.rt.review(&s.agent, "native", input).await
        } else {
            s.rt.replace(
                &s.agent,
                "native",
                Setup::replace(
                    &first,
                    json!([{"name":"one","contract_digest":entry["contract_digest"]}]),
                ),
            )
            .await
        }
    })
}
#[tokio::test]
async fn process_slots_are_finite_and_all_leases_release_on_close() {
    let s = Setup::new().await;
    let rt = Arc::new(s.rt);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let r = rt.clone();
        tasks.push(tokio::spawn(async move {
            r.scoped(std::future::pending()).await
        }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while rt.slots.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let ninth = rt.scoped(async { panic!("ninth entered") }).await;
    assert_eq!(ninth.unwrap_err().0, "observation_capacity");
    rt.owner.close();
    rt.owner.wait().await;
    for task in tasks {
        assert!(task.await.unwrap().is_err());
    }
    assert_eq!(rt.slots.available_permits(), 8);
}
