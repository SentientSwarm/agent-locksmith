use super::support::{Setup, tool};
use agent_locksmith::native_authority::{
    effective::{Pins, Snapshot},
    source::Source,
};
use serde_json::{Value, json};

async fn snapshot(s: &Setup) -> Snapshot {
    let mut tx = s.f.pool.begin().await.unwrap();
    let value = s.rt.effective(&mut tx, &s.agent, "native").await.unwrap();
    tx.commit().await.unwrap();
    value
}
async fn approve(s: &Setup, names: &[&str]) -> Value {
    let state = s.publish(names.iter().map(|n| tool(n)).collect()).await;
    let mut grants = vec![];
    for name in names {
        let r = s.review(&state, name).await;
        grants.push(json!({"name":name,"contract_digest":r["contract_digest"]}));
    }
    s.grant_for(&s.agent, &state, json!(grants)).await;
    s.rt.snapshot(&s.agent, "native").await.unwrap()
}
#[tokio::test]
async fn first_empty_list_is_a_real_pin_and_never_expands() {
    let s = Setup::new().await;
    let mut pins = Pins::default();
    assert!(pins.selected("one").is_err());
    assert!(pins.list(&snapshot(&s).await).unwrap().is_empty());
    approve(&s, &["one"]).await;
    assert!(pins.list(&snapshot(&s).await).unwrap().is_empty());
    assert!(pins.selected("one").is_err());
}
#[tokio::test]
async fn pins_filter_new_drift_and_revocation_but_allow_deliberate_exact_regrant() {
    let s = Setup::new().await;
    let state = approve(&s, &["one"]).await;
    let mut pins = Pins::default();
    assert_eq!(pins.list(&snapshot(&s).await).unwrap().len(), 1);
    let old = pins.selected("one").unwrap();
    approve(&s, &["one", "two"]).await;
    assert_eq!(pins.list(&snapshot(&s).await).unwrap().len(), 1);
    assert!(pins.selected("two").is_err());
    let current = s.rt.snapshot(&s.agent, "native").await.unwrap();
    s.grant_for(&s.agent, &current, json!([])).await;
    assert!(pins.list(&snapshot(&s).await).unwrap().is_empty());
    approve(&s, &["one"]).await;
    assert_eq!(pins.list(&snapshot(&s).await).unwrap().len(), 1);
    assert_eq!(pins.selected("one").unwrap(), old);
    assert_eq!(
        serde_json::from_value::<Source>(state["source"].clone()).unwrap(),
        old.0
    );
}
#[tokio::test]
async fn preparation_cannot_switch_generation_grant_revision_or_selection_aba() {
    let s = Setup::new().await;
    approve(&s, &["one"]).await;
    let before = snapshot(&s).await;
    s.publish(vec![tool("one")]).await;
    assert!(snapshot(&s).await.matches(&before).is_err());
    let before = snapshot(&s).await;
    approve(&s, &["one"]).await;
    assert!(snapshot(&s).await.matches(&before).is_err());
    let mut pins = Pins::default();
    pins.list(&snapshot(&s).await).unwrap();
    s.f.bindings.delete(s.f.agent_id, "native").await.unwrap();
    s.f.bindings
        .set(
            s.f.agent_id,
            "native",
            &agent_locksmith::registrations::AuthSpec::None,
        )
        .await
        .unwrap();
    assert!(pins.list(&snapshot(&s).await).is_err());
}
#[tokio::test]
async fn current_grants_require_current_fresh_observation_and_live_expiry() {
    let s = Setup::new().await;
    approve(&s, &["one"]).await;
    let mut before = snapshot(&s).await;
    before.expires_at = Some(0);
    assert!(before.fresh().is_err());
    sqlx::query("UPDATE native_observations SET observed_at=0")
        .execute(&s.f.pool)
        .await
        .unwrap();
    assert!(
        s.rt.effective(&mut s.f.pool.acquire().await.unwrap(), &s.agent, "native")
            .await
            .is_err()
    );
}
