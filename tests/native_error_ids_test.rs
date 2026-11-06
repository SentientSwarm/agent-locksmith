#[path = "native/fixture.rs"]
mod fixture;
use axum::body::to_bytes;
use fixture::*;
use serde_json::{Value, json};

async fn invalid(id: Value) {
    let f = Fixture::new("").await;
    let response = f
        .request(
            "/mcp/native",
            "POST",
            json!({"jsonrpc":"2.0","id":id,"method":"ping"}),
            None,
        )
        .await;
    let bytes = to_bytes(response.into_body(), 1024)
        .await
        .expect("bounded complete refusal");
    let message: rmcp::model::ServerJsonRpcMessage =
        serde_json::from_slice(&bytes).expect("SDK-decodable error envelope");
    assert!(matches!(message, rmcp::model::JsonRpcMessage::Error(_)));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value["id"].is_null());
    assert_eq!(value["error"]["code"], -32600);
    assert_eq!(f.runtime.snapshot().workers_created, 0);
}
#[tokio::test]
async fn object_error_id_is_null() {
    invalid(json!({"bad":true})).await;
}
#[tokio::test]
async fn array_error_id_is_null() {
    invalid(json!([1, 2])).await;
}
#[tokio::test]
async fn fractional_error_id_is_null() {
    invalid(json!(1.5)).await;
}
#[tokio::test]
async fn oversized_error_id_does_not_break_response_frame() {
    invalid(json!("x".repeat(70 * 1024))).await;
}
#[tokio::test]
async fn bounded_valid_id_is_preserved_on_method_and_params_errors() {
    let f = Fixture::new("").await;
    for (method, params, code) in [
        ("unknown/method", json!({}), -32601),
        ("ping", json!({"task":{}}), -32602),
    ] {
        let response = f
            .request(
                "/mcp/native",
                "POST",
                json!({"jsonrpc":"2.0","id":"valid","method":method,"params":params}),
                None,
            )
            .await;
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        let _: rmcp::model::ServerJsonRpcMessage = serde_json::from_slice(&bytes).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["id"], "valid");
        assert_eq!(value["error"]["code"], code);
    }
    assert_eq!(f.runtime.snapshot().workers_created, 0);
}
