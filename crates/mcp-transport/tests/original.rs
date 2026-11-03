//! A passing observation test records a failed generic response-bound hypothesis.
use axum::{Json, Router, routing::post};
type Error = Box<dyn std::error::Error + Send + Sync>;
use rmcp::{model::*, transport::streamable_http_client::StreamableHttpClient};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

#[tokio::test]
async fn json_response_ignores_the_sse_limit() -> Result<(), Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/mcp", listener.local_addr()?);
    let task = tokio::spawn(async move { axum::serve(listener, fixture()).await });
    let message = ClientJsonRpcMessage::request(
        ClientRequest::PingRequest(PingRequest::default()),
        RequestId::Number(1),
    );
    let response = reqwest::Client::new()
        .post_message_with_max_sse_event_size(
            Arc::from(url),
            message,
            None,
            None,
            HashMap::new(),
            16,
        )
        .await;
    task.abort();
    let message = response?.expect_json::<reqwest::Error>()?;
    assert!(serde_json::to_vec(&message)?.len() > 32 * 1024);
    println!("JSON_BOUND_HYPOTHESIS=FAIL configured_sse_bytes=16 accepted_json_bytes>32768");
    Ok(())
}

fn fixture() -> Router {
    Router::new().route(
        "/mcp",
        post(|| async {
            Json(json!({"jsonrpc":"2.0","id":1,"result":{
            "content":[{"type":"text","text":"x".repeat(32 * 1024)}]}}))
        }),
    )
}
