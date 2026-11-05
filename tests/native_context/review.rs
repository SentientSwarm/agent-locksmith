use super::support::{Setup, tool};
use agent_locksmith::native_authority::{effective::Pins, writes::Review};
use serde_json::{Value, json};

pub(super) fn request(state: &Value, context: Value) -> Value {
    json!({"source":state["source"],"generation":state["observation"]["generation"],
        "name":"lookup","effect":"read","context":context,
        "observed_digest":state["observation"]["manifest"]["tools"][0]["observed_digest"]})
}

#[tokio::test]
async fn context_review_is_preparation_and_list_projects_only_after_explicit_grant() {
    let s = Setup::new().await;
    let state = s.publish(vec![tool("lookup")]).await;
    let input: Review = serde_json::from_value(request(&state, json!({"key":"fixed"})))
        .expect("operator context must be accepted as a fixed typed map");
    let reviewed = s.rt.review(&s.agent, "native", input).await.unwrap();
    assert_eq!(
        reviewed["contract"]["context_profile"],
        "fixed-top-level-v1"
    );
    assert_eq!(reviewed["contract"]["tool"], tool("lookup"));
    assert_eq!(reviewed["callable_input_schema"]["properties"], json!({}));
    assert_eq!(reviewed["callable_input_schema"]["required"], json!([]));
    assert!(
        !s.rt.snapshot(&s.agent, "native").await.unwrap()["callable"]
            .as_bool()
            .unwrap()
    );
    s.grant_for(
        &s.agent,
        &state,
        json!([{"name":"lookup","contract_digest":reviewed["contract_digest"]}]),
    )
    .await;
    let snapshot =
        s.rt.effective(&mut s.f.pool.acquire().await.unwrap(), &s.agent, "native")
            .await
            .unwrap();
    assert_projection(&snapshot, &reviewed);
}

#[tokio::test]
async fn absent_and_explicit_empty_context_preserve_exact_contract_and_response() {
    let s = Setup::new().await;
    let state = s.publish(vec![tool("lookup")]).await;
    let old = s.review(&state, "lookup").await;
    let input: Review = serde_json::from_value(request(&state, json!({})))
        .expect("explicit empty context is compatible");
    let new = s.rt.review(&s.agent, "native", input).await.unwrap();
    assert_eq!(new, old);
    assert!(new["contract"].get("context_profile").is_none());
    assert!(new.get("callable_input_schema").is_none());
}

#[tokio::test]
async fn invalid_fixed_values_and_unknown_keys_leave_no_review_or_grant() {
    let s = Setup::new().await;
    let state = s.publish(vec![tool("lookup")]).await;
    for context in [json!({"key":1}), json!({"missing":"x"})] {
        let input: Review = serde_json::from_value(request(&state, context))
            .expect("typed map is validated against observed schema during review");
        assert!(s.rt.review(&s.agent, "native", input).await.is_err());
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM native_reviews")
        .fetch_one(&s.f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        s.rt.snapshot(&s.agent, "native").await.unwrap()["grant_revision"],
        Value::Null
    );
}

#[tokio::test]
async fn context_is_a_map_not_nullable_or_a_policy_language() {
    let s = Setup::new().await;
    let state = s.publish(vec![tool("lookup")]).await;
    for context in [Value::Null, json!([]), json!("path")] {
        assert!(serde_json::from_value::<Review>(request(&state, context)).is_err());
    }
}

fn assert_projection(
    snapshot: &agent_locksmith::native_authority::effective::Snapshot,
    reviewed: &Value,
) {
    let listed = Pins::default().list(snapshot).unwrap();
    assert_eq!(listed[0]["inputSchema"], reviewed["callable_input_schema"]);
}
