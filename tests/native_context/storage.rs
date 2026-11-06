use super::{review::request, support::Setup};
use agent_locksmith::native_authority::{api, contract, writes::Review};
use serde_json::{Value, json};

fn wide_tool() -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert(
        "key".into(),
        json!({"type":"array","items":{
        "type":"object","properties":{"x":{"type":"integer"}},
        "required":["x"],"additionalProperties":false}}),
    );
    for n in 0..123 {
        properties.insert(format!("field{n}"), json!({"type":"string"}));
    }
    json!({"name":"lookup","inputSchema":{"type":"object",
        "properties":properties,"required":["key"],"additionalProperties":false}})
}

fn input(state: &Value, count: usize) -> Review {
    let value = request(state, json!({"key":vec![json!({"x":0});count]}));
    api::parse(value.to_string().as_bytes())
        .expect("authoring input fits its own raw parser budget")
}

async fn accepted_control(s: &Setup, state: &Value) -> Value {
    let review =
        s.rt.review(&s.agent, "native", input(state, 1000))
            .await
            .unwrap();
    let raw = review["contract"].to_string();
    assert!(api::parse::<Value>(raw.as_bytes()).is_ok());
    s.grant_for(
        &s.agent,
        state,
        json!([{"name":"lookup","contract_digest":review["contract_digest"]}]),
    )
    .await;
    let current = s.rt.snapshot(&s.agent, "native").await.unwrap();
    let effective =
        s.rt.effective(&mut s.f.pool.acquire().await.unwrap(), &s.agent, "native")
            .await
            .unwrap();
    assert_eq!(effective.tools.len(), 1);
    current
}

async fn reject_large(s: &Setup, state: &Value) {
    let outcome = s.rt.review(&s.agent, "native", input(state, 1250)).await;
    if let Ok(value) = &outcome {
        let raw = value["contract"].to_string();
        assert!(raw.len() < 64 * 1024);
        assert!(api::parse::<Value>(raw.as_bytes()).is_err());
        let grant = Setup::replace(
            state,
            json!([{"name":"lookup","contract_digest":value["contract_digest"]}]),
        );
        let error = s.rt.replace(&s.agent, "native", grant).await.unwrap_err();
        eprintln!(
            "accepted review bytes={} but grant refused {}",
            raw.len(),
            error.0
        );
        assert_eq!(error.0, "review_invalid");
    }
    assert_eq!(
        outcome
            .expect_err("unreadable contract must refuse before INSERT")
            .0,
        "review_limit"
    );
}

#[tokio::test]
async fn combined_storage_limit_refuses_before_insert_and_preserves_current_grant() {
    let s = Setup::new().await;
    let tool = wide_tool();
    contract::tool(&tool).unwrap();
    let state = s.publish(vec![tool]).await;
    let current = accepted_control(&s, &state).await;
    reject_large(&s, &current).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM native_reviews")
        .fetch_one(&s.f.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(s.rt.snapshot(&s.agent, "native").await.unwrap(), current);
    assert_eq!(
        s.rt.effective(&mut s.f.pool.acquire().await.unwrap(), &s.agent, "native")
            .await
            .unwrap()
            .tools
            .len(),
        1
    );
}
