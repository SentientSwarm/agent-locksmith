use super::support::{Setup, tool};
use agent_locksmith::native_authority::{grants, store};
use serde_json::json;

#[tokio::test]
async fn old_success_and_failure_cannot_replace_new_complete_observation() {
    let s = Setup::new().await;
    let current = s.current().await;
    let mut tx = s.f.pool.begin().await.unwrap();
    let first = store::reserve(&mut tx, &current, &s.rt.run, None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let final_snapshot = s.publish(vec![tool("one")]).await;
    let mut tx = s.f.pool.begin().await.unwrap();
    store::failed(&mut tx, &current.source, &first)
        .await
        .unwrap();
    assert!(
        store::publish(&mut tx, &current, &first, &json!({"tools":[]}))
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert_eq!(
        s.rt.snapshot(&s.agent, "native").await.unwrap(),
        final_snapshot
    );
}
#[tokio::test]
async fn grant_replace_is_atomic_cas_and_binding_aba_clears_it() {
    let s = Setup::new().await;
    let snapshot = s.publish(vec![tool("one")]).await;
    let reviewed = s.review(&snapshot, "one").await;
    let entries = json!([{"name":"one","contract_digest":reviewed["contract_digest"]}]);
    s.grant_for(&s.agent, &snapshot, entries.clone()).await;
    assert!(
        s.rt.replace(&s.agent, "native", Setup::replace(&snapshot, json!([])))
            .await
            .is_err()
    );
    let next = s.rt.snapshot(&s.agent, "native").await.unwrap();
    let mut invalid = entries.as_array().unwrap().clone();
    invalid.push(json!({"name":"absent","contract_digest":"bad"}));
    assert!(
        s.rt.replace(&s.agent, "native", Setup::replace(&next, json!(invalid)))
            .await
            .is_err()
    );
    assert_eq!(s.rt.snapshot(&s.agent, "native").await.unwrap(), next);
    aba(&s, &next).await;
}
async fn aba(s: &Setup, next: &serde_json::Value) {
    s.f.bindings.delete(s.f.agent_id, "native").await.unwrap();
    s.f.bindings
        .set(
            s.f.agent_id,
            "native",
            &agent_locksmith::registrations::AuthSpec::None,
        )
        .await
        .unwrap();
    let current = s.current().await;
    assert!(
        current
            .matches(&serde_json::from_value(next["source"].clone()).unwrap())
            .is_err()
    );
    assert!(
        grants::entries(&mut s.f.pool.acquire().await.unwrap(), &current)
            .await
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn current_revision_and_process_run_control_freshness() {
    let s = Setup::new().await;
    let snapshot = s.publish(vec![tool("one")]).await;
    sqlx::query("UPDATE registrations SET metadata_json='{}' WHERE name='native'")
        .execute(&s.f.pool)
        .await
        .unwrap();
    s.f.refresh().await;
    s.stale(&snapshot, &s.rt.run).await;
    let new = s.publish(vec![tool("one")]).await;
    s.stale(&new, "different-process").await;
}

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
struct Dropped(Arc<AtomicBool>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
#[tokio::test]
async fn close_owns_waiting_operation_and_rejects_registration() {
    let s = Setup::new().await;
    let rt = Arc::new(s.rt);
    let done = Arc::new(AtomicBool::new(false));
    let start = Arc::new(tokio::sync::Notify::new());
    let (r, d, n) = (rt.clone(), done.clone(), start.clone());
    let task = tokio::spawn(async move {
        r.scoped(async move {
            let _lease = Dropped(d);
            n.notify_one();
            std::future::pending().await
        })
        .await
    });
    start.notified().await;
    rt.owner.close();
    rt.owner.wait().await;
    assert!(task.await.unwrap().is_err());
    assert!(done.load(Ordering::SeqCst));
    assert_eq!(rt.slots.available_permits(), 8);
    assert!(
        rt.scoped(async { panic!("must not enter after close") })
            .await
            .is_err()
    );
}
