//! Brokered routes phase 3 — the proxy on a broker route sends the route's
//! broker key and the caller's identity, never the agent's own headers,
//! and fails closed without a usable key or a `broker` selection.

#[path = "support/broker.rs"]
mod broker;

use broker::{H, broker_body, setup};
use serde_json::{Value, json};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn upstream() -> MockServer {
    let m = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&m)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&m)
        .await;
    m
}

/// A broker route `pool` on `m` with a sealed key, granted to and selected
/// by the harness agent.
async fn broker_route(h: &H, m: &MockServer, spec: Value) {
    let mut body = broker_body(&m.uri(), spec);
    body["auth"] = json!({ "kind": "none" });
    h.put_model("pool", body).await.assert_status_ok();
    h.seal("pool", "broker-key-1").await;
    h.grant(&["pool"]).await;
    h.bind("pool", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
}

fn header_values(req: &wiremock::Request, name: &str) -> Vec<String> {
    req.headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn broker_injects_key_and_identity() {
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({})).await;
    h.call("pool", "/v1/models").await.assert_status_ok();
    let reqs = m.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        header_values(&reqs[0], "authorization"),
        ["Bearer broker-key-1"]
    );
    assert_eq!(
        header_values(&reqs[0], "x-locksmith-agent"),
        std::slice::from_ref(&h.pid)
    );
    let d = h.last_audit("proxy_request").await;
    assert_eq!(d["auth_mode"], "broker");
    assert_eq!(d["auth_source"], "broker");
    assert_eq!(d["broker_key_mode"], "stored_bearer");
    assert_eq!(d["backend_kind"], "broker");
}

#[tokio::test]
async fn agent_identity_header_is_replaced() {
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({})).await;
    h.agent
        .get("/api/pool/v1/models")
        .add_header("authorization", &h.agent_bearer)
        .add_header("x-LOCKSMITH-agent", "spoofed-agent")
        .await
        .assert_status_ok();
    let reqs = m.received_requests().await.unwrap();
    assert_eq!(
        header_values(&reqs[0], "x-locksmith-agent"),
        std::slice::from_ref(&h.pid)
    );
}

#[tokio::test]
async fn identity_header_disabled_sends_none() {
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({ "identity_header": null })).await;
    h.call("pool", "/v1/models").await.assert_status_ok();
    let reqs = m.received_requests().await.unwrap();
    assert!(header_values(&reqs[0], "x-locksmith-agent").is_empty());
    assert_eq!(
        header_values(&reqs[0], "authorization"),
        ["Bearer broker-key-1"]
    );
}

#[tokio::test]
async fn header_broker_key_uses_its_header() {
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({})).await;
    h.op_req(axum::http::Method::PUT, "/models/pool/credential")
        .json(&json!({ "value": "header-key", "header": "X-Pool-Key" }))
        .await
        .assert_status_ok();
    h.call("pool", "/v1/models").await.assert_status_ok();
    let reqs = m.received_requests().await.unwrap();
    assert_eq!(header_values(&reqs[0], "x-pool-key"), ["header-key"]);
    assert!(header_values(&reqs[0], "authorization").is_empty());
}

#[tokio::test]
async fn unbound_agent_refused() {
    let h = setup().await;
    let m = upstream().await;
    let mut body = broker_body(&m.uri(), json!({}));
    body["auth"] = json!({ "kind": "none" });
    h.put_model("pool", body).await.assert_status_ok();
    h.seal("pool", "broker-key-1").await;
    h.grant(&["pool"]).await;
    let r = h.call("pool", "/v1/models").await;
    assert_eq!(r.status_code(), 403);
    assert_eq!(r.json::<Value>()["error"]["code"], "tool_not_allowed");
    assert_eq!(
        h.last_audit("authz_denied").await["reason"],
        "account_binding_missing"
    );
    assert!(m.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn dead_broker_key_fails_closed() {
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({})).await;
    sqlx::query("UPDATE credential_secrets SET tombstoned_at = unixepoch()")
        .execute(&h.pool)
        .await
        .unwrap();
    let r = h.call("pool", "/v1/models").await;
    assert_eq!(r.status_code(), 503);
    assert_eq!(r.json::<Value>()["error"]["code"], "credential_unresolved");
    assert!(m.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn unsealed_broker_key_fails_closed() {
    let h = setup().await;
    let m = upstream().await;
    let mut body = broker_body(&m.uri(), json!({}));
    body["auth"] = json!({ "kind": "none" });
    h.put_model("pool", body).await.assert_status_ok();
    h.grant(&["pool"]).await;
    h.bind("pool", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    let r = h.call("pool", "/v1/models").await;
    assert_eq!(r.status_code(), 503);
    assert_eq!(r.json::<Value>()["error"]["code"], "credential_unresolved");
    assert!(m.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn codex_profile_on_broker_skips_account_header() {
    let h = setup().await;
    let m = upstream().await;
    let mut body = broker_body(&m.uri(), json!({}));
    body["auth"] = json!({ "kind": "none" });
    body["profile"] = json!("openai-codex-responses");
    h.put_model("pool", body).await.assert_status_ok();
    h.seal("pool", "broker-key-1").await;
    h.grant(&["pool"]).await;
    h.bind("pool", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    h.agent
        .post("/api/pool/responses")
        .add_header("authorization", &h.agent_bearer)
        .json(&json!({ "model": "m", "input": "hi" }))
        .await
        .assert_status_ok();
    let reqs = m.received_requests().await.unwrap();
    let sent: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(sent["store"], false, "codex body fix-up still applies");
    assert!(header_values(&reqs[0], "chatgpt-account-id").is_empty());
    assert_eq!(
        header_values(&reqs[0], "x-locksmith-agent"),
        std::slice::from_ref(&h.pid)
    );
}

async fn labelled_upstream(label: &str) -> MockServer {
    let m = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-account-label", label)
                .set_body_string("ok"),
        )
        .mount(&m)
        .await;
    m
}

#[tokio::test]
async fn attribution_recorded_on_audit() {
    let h = setup().await;
    let m = labelled_upstream("acct-7").await;
    broker_route(
        &h,
        &m,
        json!({ "attribution": { "header": "x-account-label" } }),
    )
    .await;
    let r = h.call("pool", "/v1/models").await;
    r.assert_status_ok();
    assert_eq!(r.header("x-account-label"), "acct-7", "still forwarded");
    let d = h.last_audit("proxy_request").await;
    assert_eq!(d["broker_account"], "acct-7");
    assert!(d.get("broker_account_invalid").is_none());
}

#[tokio::test]
async fn sensitive_attribution_is_hashed() {
    let h = setup().await;
    let m = labelled_upstream("acct-7").await;
    broker_route(
        &h,
        &m,
        json!({ "attribution": { "header": "x-account-label", "sensitive": true } }),
    )
    .await;
    h.call("pool", "/v1/models").await.assert_status_ok();
    let d = h.last_audit("proxy_request").await;
    let v = d["broker_account"].as_str().unwrap();
    assert!(v.starts_with("sha256:") && !v.contains("acct-7"), "{v}");
}

#[tokio::test]
async fn invalid_attribution_flagged() {
    let h = setup().await;
    let m = labelled_upstream("two words").await;
    broker_route(
        &h,
        &m,
        json!({ "attribution": { "header": "x-account-label" } }),
    )
    .await;
    h.call("pool", "/v1/models").await.assert_status_ok();
    let d = h.last_audit("proxy_request").await;
    assert_eq!(d["broker_account_invalid"], true);
    assert!(d.get("broker_account").is_none());
}
