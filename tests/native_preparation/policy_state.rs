use super::support::Setup;
use agent_locksmith::{
    native_authority::{policy::Policy, writes},
    registrations::AuthSpec,
};
use serde_json::{Value, json};

async fn select(s: &Setup, policy: Policy) {
    let mut r = s.f.repo.get("native").await.unwrap().unwrap();
    r.mcp.as_mut().unwrap().contract_policy = policy;
    s.f.repo.upsert(&r).await.unwrap();
    s.f.agents
        .update_policy(
            &s.agent,
            Some(Some(vec!["native".into()])),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    s.f.bindings
        .set(s.f.agent_id, "native", &AuthSpec::None)
        .await
        .unwrap();
    s.f.refresh().await;
}
fn input(state: &Value) -> Value {
    json!({"source":state["source"],"generation":state["observation"]["generation"],"name":"empty","observed_digest":state["observation"]["manifest"]["tools"][0]["observed_digest"],"effect":"read","contract_policy":"finite-v2","input_restriction":"empty-arguments"})
}
#[tokio::test]
async fn policy_selection_review_marker_and_toggle_never_revive_grants() {
    let s = Setup::new().await;
    let tool = json!({"name":"empty","_meta":{"inert":"do not execute"},"inputSchema":{"type":"object","properties":{}}});
    let old = s.publish(vec![tool.clone()]).await;
    let forged: writes::Review = serde_json::from_value(input(&old)).unwrap();
    assert!(s.rt.review(&s.agent, "native", forged).await.is_err());
    select(&s, Policy::V2).await;
    let state = s.publish(vec![tool.clone()]).await;
    assert_eq!(state["source"]["contract_policy"], "finite-v2");
    for key in ["contract_policy", "input_restriction"] {
        let mut bad = input(&state);
        bad.as_object_mut().unwrap().remove(key);
        assert!(
            s.rt.review(&s.agent, "native", serde_json::from_value(bad).unwrap())
                .await
                .is_err()
        );
    }
    let r =
        s.rt.review(
            &s.agent,
            "native",
            serde_json::from_value(input(&state)).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r["contract"]["tool"], tool);
    let entries = json!([{"name":"empty","contract_digest":r["contract_digest"]}]);
    s.grant_for(&s.agent, &state, entries.clone()).await;
    let current = s.rt.snapshot(&s.agent, "native").await.unwrap();
    assert_eq!(current["effective_tools"], json!(["empty"]));
    select(&s, Policy::V1).await;
    let v1 = s.rt.snapshot(&s.agent, "native").await.unwrap();
    assert!(v1["source"].get("contract_policy").is_none());
    assert_eq!(v1["effective_tools"], json!([]));
    select(&s, Policy::V2).await;
    let next = s.publish(vec![tool]).await;
    assert!(
        s.rt.replace(&s.agent, "native", Setup::replace(&next, entries))
            .await
            .is_err()
    );
    assert_ne!(old["source"], next["source"]);
    assert!(
        s.rt.review(
            &s.agent,
            "native",
            serde_json::from_value(input(&state)).unwrap()
        )
        .await
        .is_err()
    );
}
