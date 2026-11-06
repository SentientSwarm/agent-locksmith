use super::{calls, commit, discovery, fixture::Fixture, flow, wire};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preparation_rechecks_current_lifecycle_source_and_observation() {
    for sql in [
        "UPDATE agents SET expires_at=1",
        "UPDATE agents SET revoked_at=1",
        "UPDATE native_observations SET observed_at=1",
        "UPDATE native_observations SET generation='replaced'",
        "DELETE FROM native_tool_grants",
        "DELETE FROM agent_credential_overrides",
        "UPDATE registrations SET disabled=1",
        "UPDATE registrations SET upstream='https://example.com/mcp'",
    ] {
        refused_after_preparation(sql).await;
    }
}

async fn refused_after_preparation(sql: &str) {
    let (mut f, receiver, a, session, pool) = commit::setup().await;
    behavior(&f, json!({"prepare_hold":"initialize"}));
    let call = refusal(&f, &a, &session);
    let alter = async {
        commit::arrived(&f, "initialize").await;
        sqlx::query(sql).execute(&pool).await.unwrap();
        std::fs::write(f.path().join("release-initialize.json"), "go").unwrap();
    };
    tokio::join!(call, alter);
    assert!(calls::effects(&f).is_empty(), "{sql}");
    let admissions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(admissions, 0, "{sql}");
    pool.close().await;
    f.stop();
    receiver.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unrelated_drift_preserves_pins_but_returned_tool_needs_regrant() {
    let (mut f, receiver, a, session, pool) = commit::setup().await;
    let id = a["public_id"].as_str().unwrap();
    let first = flow::show(&f, id)["observation"]["manifest"]["tools"][0]["tool"].clone();
    let mut other = first.clone();
    other["name"] = "new_unapproved_tool".into();
    manifest(&f, json!([first, other]));
    flow::observe(&f, id);
    assert!(calls::call(&f, &a, &session, 2, json!({})).await["result"].is_object());
    manifest(&f, json!([]));
    flow::observe(&f, id);
    assert!(calls::call(&f, &a, &session, 3, json!({})).await["error"].is_object());
    manifest(&f, json!([first]));
    flow::observe(&f, id);
    assert!(calls::call(&f, &a, &session, 4, json!({})).await["error"].is_object());
    discovery::grant(&f, id);
    assert!(calls::call(&f, &a, &session, 5, json!({})).await["result"].is_object());
    assert_eq!(calls::effects(&f).len(), 2);
    pool.close().await;
    f.stop();
    receiver.stop();
}

fn manifest(f: &Fixture, tools: serde_json::Value) {
    std::fs::write(
        f.path().join("manifest.json"),
        json!({"tools":tools}).to_string(),
    )
    .unwrap();
}
fn behavior(f: &Fixture, value: serde_json::Value) {
    std::fs::write(f.path().join("behavior.json"), value.to_string()).unwrap();
}

async fn refusal(f: &Fixture, a: &serde_json::Value, session: &str) {
    let token = a["token"].as_str().unwrap();
    let request = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_record","arguments":{}}});
    let body = wire::post(f, token, Some(session), request)
        .await
        .text()
        .await
        .unwrap();
    if body.is_empty() {
        let ping = wire::post(
            f,
            token,
            Some(session),
            json!({"jsonrpc":"2.0","id":3,"method":"ping"}),
        )
        .await;
        assert!(
            !ping.status().is_success(),
            "empty stream must have retired authority"
        );
    } else {
        let value: serde_json::Value = serde_json::from_str(
            body.lines()
                .find_map(|l| l.strip_prefix("data: "))
                .unwrap_or(&body),
        )
        .unwrap();
        assert!(value["error"].is_object(), "{value}");
    }
}
