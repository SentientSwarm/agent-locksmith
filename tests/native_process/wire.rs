use super::fixture::Fixture;
use serde_json::{Value, json};

pub async fn post(
    f: &Fixture,
    token: &str,
    session: Option<&str>,
    body: Value,
) -> reqwest::Response {
    let mut r = f
        .http
        .post(f.url("/mcp/native"))
        .bearer_auth(token)
        .header("accept", "application/json, text/event-stream")
        .json(&body);
    if let Some(id) = session {
        r = r
            .header("mcp-session-id", id)
            .header("mcp-protocol-version", "2025-11-25");
    }
    r.send().await.unwrap()
}
pub async fn open(f: &Fixture, token: &str) -> String {
    let r = post(f, token, None, init()).await;
    assert_eq!(r.status(), 200);
    let id = r.headers()["mcp-session-id"].to_str().unwrap().to_owned();
    assert!(r.text().await.unwrap().contains("2025-11-25"));
    assert_eq!(
        post(
            f,
            token,
            Some(&id),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .await
        .status(),
        202
    );
    id
}
pub fn init() -> Value {
    json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
    "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}})
}
pub async fn exercise(f: &mut Fixture, a: &Value) {
    let token = a["token"].as_str().unwrap();
    let id = open(f, token).await;
    unsupported(f, token, &id).await;
    let r = post(
        f,
        token,
        Some(&id),
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999}}),
    )
    .await;
    assert_eq!(r.status(), 202);
    drop(get(f, token, &id).await);
    let id = open(f, token).await;
    assert_eq!(
        f.http
            .delete(f.url("/mcp/native"))
            .bearer_auth(token)
            .header("mcp-session-id", &id)
            .header("mcp-protocol-version", "2025-11-25")
            .send()
            .await
            .unwrap()
            .status(),
        202
    );
    revoke(f, a, &id).await;
}

async fn unsupported(f: &Fixture, token: &str, id: &str) {
    for method in ["sampling/createMessage", "forged/method"] {
        let r = post(
            f,
            token,
            Some(id),
            json!({"jsonrpc":"2.0","id":10,"method":method}),
        )
        .await;
        assert!(r.text().await.unwrap().contains("-32601"));
    }
}

pub async fn get(f: &Fixture, token: &str, id: &str) -> reqwest::Response {
    let r = f
        .http
        .get(f.url("/mcp/native"))
        .bearer_auth(token)
        .header("accept", "text/event-stream")
        .header("mcp-session-id", id)
        .header("mcp-protocol-version", "2025-11-25")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r
}

async fn revoke(f: &Fixture, a: &Value, id: &str) {
    let token = a["token"].as_str().unwrap();
    f.op(&["agent", "revoke", a["public_id"].as_str().unwrap()]);
    assert_eq!(
        post(
            f,
            token,
            Some(id),
            json!({"jsonrpc":"2.0","id":1,"method":"ping"})
        )
        .await
        .status(),
        401
    );
}
