use super::{
    review::request,
    support::{Setup, tool},
};
use agent_locksmith::native_authority::{api, writes::Review};
use serde_json::{Value, json};

#[tokio::test]
async fn duplicate_context_members_and_unknown_fields_refuse_raw_import() {
    let s = Setup::new().await;
    let state = s.publish(vec![tool("lookup")]).await;
    let text = request(&state, json!({"key":"fixed"})).to_string();
    let duplicate = text.replace("\"key\":\"fixed\"", r#""key":"fixed","\u006bey":"fixed""#);
    assert!(api::parse::<Review>(duplicate.as_bytes()).is_err());
    let mut value = request(&state, json!({"key":"fixed"}));
    value["unknown"] = true.into();
    assert!(api::parse::<Review>(value.to_string().as_bytes()).is_err());
    assert!(api::parse::<Review>(text.as_bytes()).is_ok());
}

#[tokio::test]
async fn aggregate_preview_refusal_precedes_review_insert() {
    let s = Setup::new().await;
    let mut t = tool("lookup");
    let mut properties = serde_json::Map::new();
    for n in 0..20 {
        properties.insert(
            format!("field{n}"),
            json!({"type":"string","description":"d".repeat(1000)}),
        );
    }
    t["inputSchema"] =
        json!({"type":"object","properties":properties,"additionalProperties":false});
    let state = s.publish(vec![t]).await;
    let input: Review =
        serde_json::from_value(request(&state, json!({"field0":"v".repeat(30000)}))).unwrap();
    assert_eq!(
        s.rt.review(&s.agent, "native", input).await.unwrap_err().0,
        "review_limit"
    );
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
