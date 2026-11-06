mod support;
use locksmith_mcp_transport::{Client, Error, Limits};
use rmcp::transport::streamable_http_client::StreamableHttpClient;
use serde_json::Value;
use std::collections::HashMap;
use support::process::Receiver;

fn accept(_: &Value) -> Result<(), Error> {
    Ok(())
}
fn reject(_: &Value) -> Result<(), Error> {
    Err(Error("fixture_raw_refusal"))
}
fn client(receiver: &Receiver, budget: usize, validate: fn(&Value) -> Result<(), Error>) -> Client {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let port = reqwest::Url::parse(&receiver.url).unwrap().port().unwrap();
    Client::pinned(
        Limits::default(),
        vec![reqwest::Certificate::from_pem(receiver.certificate.as_bytes()).unwrap()],
        &receiver.url,
        vec![([127, 0, 0, 1], port).into()],
        budget,
        validate,
    )
    .unwrap()
}
async fn post(client: &Client, url: &str) -> Result<(), String> {
    let message = serde_json::from_value(serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"pin-test","version":"1"}}})).unwrap();
    client
        .post_message(
            url.into(),
            message,
            None,
            Some("synthetic-test-token".into()),
            HashMap::new(),
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}
#[tokio::test]
async fn verified_tls_exact_endpoint_and_aggregate_budget_across_clones() {
    let receiver = Receiver::start().await.unwrap();
    let probe = client(&receiver, 4096, accept);
    post(&probe, &receiver.url).await.unwrap();
    let bytes = probe.metrics().snapshot().received;
    let bounded = client(&receiver, bytes, accept);
    post(&bounded, &receiver.url).await.unwrap();
    assert!(
        post(&bounded.clone(), &receiver.url)
            .await
            .unwrap_err()
            .contains("aggregate_bytes")
    );
    assert_eq!(bounded.metrics().snapshot().active_bodies, 0);
    let counts = receiver.counts().unwrap();
    assert!(
        post(&probe, &format!("{}/other", receiver.url))
            .await
            .is_err()
    );
    assert_eq!(counts, receiver.counts().unwrap());
}
#[tokio::test]
async fn raw_validator_refuses_before_sdk_projection_and_wrong_pin_never_falls_back() {
    let receiver = Receiver::start().await.unwrap();
    assert!(
        post(&client(&receiver, 4096, reject), &receiver.url)
            .await
            .unwrap_err()
            .contains("fixture_raw_refusal")
    );
    let counts = receiver.counts().unwrap();
    let port = reqwest::Url::parse(&receiver.url).unwrap().port().unwrap();
    let wrong = Client::pinned(
        Limits::default(),
        vec![],
        &receiver.url,
        vec![([127, 0, 0, 2], port).into()],
        4096,
        accept,
    )
    .unwrap();
    assert!(post(&wrong, &receiver.url).await.is_err());
    assert_eq!(counts, receiver.counts().unwrap());
}
#[test]
fn literal_pin_and_url_grammar_are_checked_without_io() {
    for endpoint in [
        "http://localhost:443/",
        "https://user@localhost/",
        "https://localhost/?x",
        "https://localhost/#x",
        "https://127.0.0.2/",
    ] {
        assert!(
            Client::pinned(
                Limits::default(),
                vec![],
                endpoint,
                vec![([127, 0, 0, 1], 443).into()],
                4096,
                accept
            )
            .is_err()
        );
    }
}
