#[path = "native/fixture.rs"]
mod fixture;
use axum::{body::Body, http::Request};
use fixture::*;
use serde_json::{Value, json};
use tower::ServiceExt;

fn request(f: &Fixture, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/mcp/native")
        .header("host", "localhost")
        .header("authorization", &f.bearer)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(body))
        .unwrap()
}
#[tokio::test]
async fn ingress_limit_and_deadline_include_authentication_pool_wait() {
    let f = Fixture::new("mcp:\n  ingress: 1\n  request_ms: 150\n").await;
    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(f.pool.acquire().await.unwrap());
    }
    let app = f.app.clone();
    let req = request(&f, init(0).to_string());
    let pending = tokio::spawn(async move { app.oneshot(req).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    assert_eq!(
        f.app
            .clone()
            .oneshot(request(&f, init(1).to_string()))
            .await
            .unwrap()
            .status(),
        429
    );
    assert_eq!(pending.await.unwrap().status(), 408);
    drop(held);
    assert_eq!(f.runtime.snapshot().workers_created, 0);
    let session = f.open().await;
    drop(
        f.request("/mcp/native", "DELETE", Value::Null, Some(&session))
            .await,
    );
    released(&f).await;
}
#[tokio::test]
async fn malformed_or_oversized_inputs_allocate_no_session() {
    let f = Fixture::new("mcp:\n  request_bytes: 1024\n").await;
    for body in [
        "{".into(),
        "[]".into(),
        format!("{}0{}", "[".repeat(33), "]".repeat(33)),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":2,\"method\":\"initialize\"}".into(),
    ] {
        let response = f.app.clone().oneshot(request(&f, body)).await.unwrap();
        assert!(rpc(response).await.get("error").is_some());
    }
    let response = f
        .app
        .clone()
        .oneshot(request(&f, "x".repeat(1025)))
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    assert_eq!(f.runtime.snapshot().workers_created, 0);
}
#[tokio::test]
async fn native_origin_is_exact_and_http_policy_is_unchanged() {
    let f = Fixture::new("mcp:\n  allowed_origins: ['https://consumer.example']\n").await;
    let mut req = request(&f, init(0).to_string());
    req.headers_mut()
        .insert("origin", "https://consumer.example:444".parse().unwrap());
    assert_eq!(f.app.clone().oneshot(req).await.unwrap().status(), 403);
    let mut req = request(&f, init(0).to_string());
    req.headers_mut()
        .insert("origin", "https://consumer.example:443".parse().unwrap());
    let response = f.app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), 200);
    drop(response);
    released(&f).await;
    let mut req = request(&f, String::new());
    *req.uri_mut() = "/livez".parse().unwrap();
    *req.method_mut() = axum::http::Method::GET;
    req.headers_mut()
        .insert("origin", "https://arbitrary.example".parse().unwrap());
    assert_eq!(f.app.clone().oneshot(req).await.unwrap().status(), 200);
}
#[tokio::test]
async fn session_headers_are_not_foreign_identity_or_connection_authority() {
    let f = Fixture::new("").await;
    let session = f.open().await;
    assert_eq!(
        f.request(
            "/mcp/other",
            "POST",
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            Some(&session)
        )
        .await
        .status(),
        404
    );
    let mut req = request(&f, init(0).to_string());
    req.headers_mut().remove("authorization");
    assert_eq!(f.app.clone().oneshot(req).await.unwrap().status(), 401);
    assert_eq!(
        rpc(f.call(&session, 1, "ping").await).await["result"],
        json!({})
    );
    f.runtime.shutdown().await;
}
#[tokio::test]
async fn native_discovery_never_advertises_http_or_credential_material() {
    let f = Fixture::new("").await;
    let response = f.request("/tools", "GET", Value::Null, None).await;
    let value = rpc(response).await;
    let text = value.to_string();
    assert!(text.contains("/mcp/native"));
    assert!(!text.contains("/api/native"));
    assert!(!text.contains("example.com"));
    assert!(!text.contains("auth_spec"));
    assert!(text.contains("not_checked"));
}
