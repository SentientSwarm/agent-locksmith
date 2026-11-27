//! AGENT-378: store support for refreshing a stale observation in place.
use super::support::{Setup, tool};
use agent_locksmith::native_authority::{
    contract,
    store::{self, Renewal},
};
use serde_json::{Value, json};

fn manifest(tools: Vec<Value>) -> Value {
    json!({"tools":tools.into_iter().map(|t|json!({"observed_digest":contract::observed(&t),"tool":t})).collect::<Vec<_>>()})
}
async fn approve(s: &Setup, names: &[&str]) {
    let state = s.publish(names.iter().map(|n| tool(n)).collect()).await;
    let mut grants = vec![];
    for name in names {
        let r = s.review(&state, name).await;
        grants.push(json!({"name":name,"contract_digest":r["contract_digest"]}));
    }
    s.grant_for(&s.agent, &state, json!(grants)).await;
}
async fn sql(s: &Setup, statement: &str) {
    sqlx::query(statement).execute(&s.f.pool).await.unwrap();
}
async fn age(s: &Setup, seconds: i64) {
    sqlx::query("UPDATE native_observations SET observed_at=?")
        .bind(store::now() - seconds)
        .execute(&s.f.pool)
        .await
        .unwrap();
}
async fn candidate(s: &Setup) -> Option<store::Candidate> {
    let current = s.current().await;
    let mut c = s.f.pool.acquire().await.unwrap();
    store::candidate(&mut c, &current, &s.rt.run, current.agent)
        .await
        .unwrap()
}
async fn row(s: &Setup) -> (String, i64) {
    sqlx::query_as("SELECT generation,observed_at FROM native_observations")
        .fetch_one(&s.f.pool)
        .await
        .unwrap()
}
async fn renew(
    s: &Setup,
    generation: &str,
    tools: Vec<Value>,
) -> agent_locksmith::native_authority::Result<Renewal> {
    let current = s.current().await;
    let mut tx = s.f.pool.begin().await.unwrap();
    let result = store::renew(&mut tx, &current, &s.rt.run, generation, &manifest(tools)).await;
    tx.commit().await.unwrap();
    result
}
async fn effective_names(s: &Setup) -> Vec<String> {
    let mut tx = s.f.pool.begin().await.unwrap();
    let snapshot = s.rt.effective(&mut tx, &s.agent, "native").await.unwrap();
    tx.commit().await.unwrap();
    snapshot.tools.keys().cloned().collect()
}

#[tokio::test]
async fn candidate_requires_a_ready_current_row() {
    let s = Setup::new().await;
    approve(&s, &["one"]).await;
    age(&s, 55).await;
    assert!(candidate(&s).await.is_some_and(|c| c.same_run));
    age(&s, 10).await;
    assert!(candidate(&s).await.is_none(), "fresh rows need no refresh");
    age(&s, 0).await;
    sql(&s, "UPDATE native_observations SET run_id='old'").await;
    assert!(candidate(&s).await.is_some_and(|c| !c.same_run));
    age(&s, 55).await;
    sql(&s, "UPDATE native_observations SET status='pending'").await;
    assert!(
        candidate(&s).await.is_none(),
        "pending rows are the operator's"
    );
    sql(&s, "UPDATE native_observations SET status='ready',registration_revision=registration_revision+1").await;
    assert!(
        candidate(&s).await.is_none(),
        "a changed registration needs the operator"
    );
}
#[tokio::test]
async fn candidate_requires_the_agents_own_grant() {
    let s = Setup::new().await;
    s.publish(vec![tool("one")]).await;
    age(&s, 55).await;
    assert!(candidate(&s).await.is_none());
}
#[tokio::test]
async fn renew_keeps_generation_when_unchanged() {
    let s = Setup::new().await;
    approve(&s, &["one"]).await;
    age(&s, 55).await;
    let (generation, _) = row(&s).await;
    assert!(matches!(
        renew(&s, &generation, vec![tool("one")]).await,
        Ok(Renewal::Unchanged)
    ));
    let (after, observed_at) = row(&s).await;
    assert_eq!(after, generation);
    assert!(store::now() - observed_at <= 2);
    assert_eq!(effective_names(&s).await, ["one"]);
}
#[tokio::test]
async fn renew_mints_generation_and_invalidates_drift() {
    let s = Setup::new().await;
    approve(&s, &["one", "two"]).await;
    age(&s, 55).await;
    let (generation, _) = row(&s).await;
    let mut changed = tool("two");
    changed["description"] = "Read another record".into();
    let result = renew(&s, &generation, vec![tool("one"), changed]).await;
    assert!(matches!(result, Ok(Renewal::Changed { invalidated: 1 })));
    assert_ne!(row(&s).await.0, generation);
    assert_eq!(effective_names(&s).await, ["one"]);
}
#[tokio::test]
async fn renew_refuses_a_replaced_generation() {
    let s = Setup::new().await;
    approve(&s, &["one"]).await;
    age(&s, 55).await;
    let before = row(&s).await;
    let err = renew(&s, "replaced", vec![tool("one")])
        .await
        .err()
        .unwrap();
    assert_eq!(err.0, "observation_conflict");
    assert_eq!(row(&s).await, before);
}
#[tokio::test]
async fn refresh_is_keyed_by_account() {
    let s = Setup::new().await;
    approve(&s, &["one"]).await;
    age(&s, 55).await;
    sql(&s, "INSERT INTO native_observations(instance,account_key,generation,status,run_id,registration_revision,observed_at,manifest) SELECT instance,'other-account','other','ready',run_id,registration_revision,1,manifest FROM native_observations").await;
    let generation: String = sqlx::query_scalar(
        "SELECT generation FROM native_observations WHERE account_key<>'other-account'",
    )
    .fetch_one(&s.f.pool)
    .await
    .unwrap();
    renew(&s, &generation, vec![tool("one")]).await.unwrap();
    let other: i64 = sqlx::query_scalar(
        "SELECT observed_at FROM native_observations WHERE account_key='other-account'",
    )
    .fetch_one(&s.f.pool)
    .await
    .unwrap();
    assert_eq!(other, 1);
}
