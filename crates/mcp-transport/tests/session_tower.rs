mod session_support;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use locksmith_mcp_transport::{
    Client, Limits,
    sessions::{Config, Pool, Scoped},
};
use rmcp::{
    ServiceExt,
    transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService},
};
use session_support::*;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt as _;

fn sdk(pool: &Pool<()>) -> StreamableHttpService<Handler, Scoped<()>> {
    let mut config = StreamableHttpServerConfig::default();
    config.legacy_session_mode = true;
    StreamableHttpService::new(
        || Ok(Handler::default()),
        Arc::new(scoped(pool, "a", "x", "1")),
        config,
    )
}
fn pool() -> Pool<()> {
    Pool::new(Config {
        handshake: Duration::from_secs(3),
        idle: Duration::from_secs(30),
        lifetime: Duration::from_secs(30),
        ..config()
    })
    .unwrap()
}
fn request() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "localhost")
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&init()).unwrap()))
        .unwrap()
}
#[tokio::test]
async fn dropping_unpolled_initialize_body_retires_actual_tower_session() {
    let pool = pool();
    let response = sdk(&pool).oneshot(request()).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(pool.snapshot().workers_created, 1);
    drop(response);
    tokio::time::timeout(Duration::from_secs(1), async {
        while pool.snapshot().entries != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("unpolled initial response must retire without explicit shutdown");
    assert_eq!(pool.snapshot().workers_joined, 1);
    assert_eq!(pool.snapshot().services_joined, 1);
}
#[tokio::test]
async fn consuming_initialize_event_does_not_require_polling_eof() {
    let pool = pool();
    let mut response = sdk(&pool).oneshot(request()).await.unwrap();
    let mut saw_response = false;
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.unwrap();
        if let Some(data) = frame.data_ref()
            && String::from_utf8_lossy(data).contains("\"result\"")
        {
            saw_response = true;
            break;
        }
    }
    assert!(saw_response);
    drop(response);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(pool.snapshot().active, 1);
    pool.shutdown().await;
}
#[tokio::test]
async fn real_sdk_client_continues_after_initialize_and_ping_results() {
    let pool = pool();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let app = axum::Router::new().nest_service("/mcp", sdk(&pool));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = Client::new(Limits::default(), vec![]).unwrap();
    let service = Client::client_config()
        .serve(client.transport(url, None))
        .await
        .unwrap();
    for _ in 0..2 {
        service
            .peer()
            .send_request(rmcp::model::ClientRequest::PingRequest(Default::default()))
            .await
            .unwrap();
    }
    assert_eq!(pool.snapshot().active, 1);
    service.cancel().await.unwrap();
    pool.shutdown().await;
    server.abort();
    let _ = server.await;
    assert_eq!(pool.snapshot().workers_joined, 1);
    assert_eq!(pool.snapshot().services_joined, 1);
}
