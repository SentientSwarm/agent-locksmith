use super::support::{Setup, tool};
use agent_locksmith::{
    native_authority::{control::Control, dispatch::Invocation},
    repo::AuditRepository,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn invalid_arguments_have_safe_terminal_diagnostic_without_admission() {
    let s = Setup::new().await;
    let state = s.publish(vec![tool("lookup")]).await;
    let r = s.review(&state, "lookup").await;
    s.grant_for(
        &s.agent,
        &state,
        json!([{"name":"lookup","contract_digest":r["contract_digest"]}]),
    )
    .await;
    let call = invocation(&s, &state, &r);
    let control = Control {
        request: CancellationToken::new(),
        session: CancellationToken::new(),
        deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(2),
    };
    let error =
        s.rt.dispatch(call, control, &AuditRepository::new(s.f.pool.clone()))
            .await
            .unwrap_err();
    assert_eq!(error.0, "argument_schema");
    assert_diagnostic(&s).await;
}

fn invocation(s: &Setup, state: &Value, r: &Value) -> Invocation {
    Invocation {
        agent: s.agent.clone(),
        connection: "native".into(),
        name: "lookup".into(),
        source: serde_json::from_value(state["source"].clone()).unwrap(),
        digest: r["contract_digest"].as_str().unwrap().into(),
        arguments: json!({"unknown":"payload-canary"}),
    }
}

async fn assert_diagnostic(s: &Setup) {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit WHERE event='native_tool_denied'")
            .fetch_all(&s.f.pool)
            .await
            .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "refused captured call needs a terminal diagnostic"
    );
    let detail: Value = serde_json::from_str(&rows[0]).unwrap();
    assert_eq!(detail["phase"], "not_admitted");
    assert_eq!(detail["reason"], "argument_schema");
    assert!(detail["operation_id"].is_string());
    assert!(!rows[0].contains("payload-canary"));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
        .fetch_one(&s.f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
