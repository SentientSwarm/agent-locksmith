#[path = "native/fixture.rs"]
mod fixture;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use fixture::*;
use serde_json::{Value, json};
use tower::ServiceExt;

#[tokio::test]
async fn bounded_progress_metadata_works_but_unknown_and_task_metadata_do_not() {
    let f = Fixture::new("").await;
    let id = f.open().await;
    for (i, meta) in [
        json!({}),
        json!({"progressToken":7}),
        json!({"progressToken":"bounded"}),
    ]
    .into_iter()
    .enumerate()
    {
        let body = json!({"jsonrpc":"2.0","id":i+1,"method":"tools/list","params":{"_meta":meta}});
        assert_eq!(
            rpc(f.request("/mcp/native", "POST", body, Some(&id)).await).await["result"]["tools"],
            json!([])
        );
    }
    for meta in [
        json!({"unknown":true}),
        json!({"io.modelcontextprotocol/related-task":{"taskId":"x"}}),
        json!({"progressToken":null}),
    ] {
        let body = json!({"jsonrpc":"2.0","id":9,"method":"ping","params":{"_meta":meta}});
        assert_eq!(
            rpc(f.request("/mcp/native", "POST", body, Some(&id)).await).await["error"]["code"],
            -32602
        );
    }
    f.runtime.shutdown().await;
}
#[tokio::test]
async fn sdk_message_budget_retires_before_later_ids_can_replay() {
    let f = Fixture::new("mcp:\n  messages: 2\n").await;
    let id = f.open().await;
    // Initialize and initialized already consume the two SDK messages.
    let r = f.call(&id, 1, "ping").await;
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers()["retry-after"], "1");
    released(&f).await;
    assert_eq!(f.call(&id, 0, "ping").await.status(), 404);
}
#[tokio::test]
async fn second_get_has_typed_backoff_and_retires_session() {
    let f = Fixture::new("mcp:\n  response_ms: 150\n").await;
    let id = f.open().await;
    let first = f
        .request("/mcp/native", "GET", Value::Null, Some(&id))
        .await;
    assert_eq!(first.status(), 200);
    let second = f
        .request("/mcp/native", "GET", Value::Null, Some(&id))
        .await;
    assert_eq!(second.status(), 429);
    assert_eq!(second.headers()["retry-after"], "1");
    let _ = to_bytes(first.into_body(), 262144).await;
    released(&f).await;
}
#[tokio::test]
async fn shared_and_identityless_modes_cannot_enter_native_lifecycle() {
    for auth in [
        "",
        "inbound_auth:\n  mode: bearer\n  token: synthetic-shared\n",
    ] {
        let cfg =
            agent_locksmith::config::parse_config_str(&format!("listen:\n  port: 9200\n{auth}"))
                .unwrap();
        let app = agent_locksmith::app::build_app(cfg);
        let req = Request::builder()
            .method("POST")
            .uri("/mcp/native")
            .header("host", "localhost")
            .header("authorization", "Bearer synthetic-shared")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(Body::from(init(0).to_string()))
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), 401);
    }
}
#[tokio::test]
async fn disabled_and_pending_activation_do_not_fall_back_to_runtime_catalog() {
    let f = Fixture::new("").await;
    let mut r = f.repo.get("native").await.unwrap().unwrap();
    r.description = "pending".into();
    f.repo.upsert(&r).await.unwrap();
    assert_eq!(
        f.request("/mcp/native", "POST", init(0), None)
            .await
            .status(),
        503
    );
    r.disabled = true;
    f.repo.upsert(&r).await.unwrap();
    assert_eq!(
        f.request("/mcp/native", "POST", init(0), None)
            .await
            .status(),
        404
    );
    assert_eq!(f.runtime.snapshot().workers_created, 0);
}
#[tokio::test]
async fn ipv6_host_and_duplicate_security_header_boundaries() {
    let f = Fixture::new("").await;
    let req = || {
        Request::builder()
            .method("POST")
            .uri("/mcp/native")
            .header("host", "[::1]:9200")
            .header("authorization", &f.bearer)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
    };
    let duplicate = req()
        .header("mcp-protocol-version", "2025-11-25")
        .header("mcp-protocol-version", "2025-11-25")
        .body(Body::from(init(0).to_string()))
        .unwrap();
    assert_eq!(
        f.app.clone().oneshot(duplicate).await.unwrap().status(),
        400
    );
    let r = f
        .app
        .clone()
        .oneshot(req().body(Body::from(init(0).to_string())).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    drop(r);
    released(&f).await;
}

#[tokio::test]
async fn held_get_response_deadline_releases_session() {
    let f = Fixture::new("mcp:\n  response_ms: 150\n").await;
    let id = f.open().await;
    let first = f
        .request("/mcp/native", "GET", Value::Null, Some(&id))
        .await;
    assert_eq!(first.status(), 200);
    assert!(to_bytes(first.into_body(), 262144).await.is_err());
    released(&f).await;
    assert_eq!(
        f.runtime.snapshot().workers_created,
        f.runtime.snapshot().workers_joined
    );
}
