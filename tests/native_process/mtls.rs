use super::{fixture::Fixture, wire};
use serde_json::{Value, json};

pub async fn exercise(f: &Fixture, agent: &Value) {
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .add_root_certificate(reqwest::Certificate::from_pem(f.pki.ca.as_bytes()).unwrap())
        .identity(reqwest::Identity::from_pem(f.pki.identity.as_bytes()).unwrap())
        .build()
        .unwrap();
    assert_eq!(request(f, &http, None, wire::init()).await.status(), 401);
    f.op(&[
        "agent",
        "set-cert-identity",
        agent["public_id"].as_str().unwrap(),
        "native-client",
    ]);
    let response = request(f, &http, None, wire::init()).await;
    assert_eq!(response.status(), 200);
    let id = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(response.text().await.unwrap().contains("2025-11-25"));
    complete(f, &http, &id).await;
}
async fn request(
    f: &Fixture,
    http: &reqwest::Client,
    id: Option<&str>,
    value: Value,
) -> reqwest::Response {
    let mut r = http
        .post(f.url("/mcp/native"))
        .header("accept", "application/json, text/event-stream")
        .json(&value);
    if let Some(id) = id {
        r = r
            .header("mcp-session-id", id)
            .header("mcp-protocol-version", "2025-11-25");
    }
    r.send().await.unwrap()
}

async fn complete(f: &Fixture, http: &reqwest::Client, id: &str) {
    let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    assert_eq!(request(f, http, Some(id), initialized).await.status(), 202);
    let response = request(
        f,
        http,
        Some(id),
        json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    )
    .await;
    assert_eq!(response.status(), 200);
    let _ = response.bytes().await.unwrap();
    delete(f, http, id).await;
}

async fn delete(f: &Fixture, http: &reqwest::Client, id: &str) {
    assert_eq!(
        http.delete(f.url("/mcp/native"))
            .header("mcp-session-id", id)
            .header("mcp-protocol-version", "2025-11-25")
            .send()
            .await
            .unwrap()
            .status(),
        202
    );
}
