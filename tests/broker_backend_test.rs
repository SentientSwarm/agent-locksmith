//! Brokered routes phase 3 — a declared backend can be a broker. Switching
//! onto it never carries an upstream binding across, its key is sealed
//! without echo, and switching back restores the upstream bindings.

#[path = "support/broker.rs"]
mod broker;

use axum::http::Method;
use broker::{H, setup, upstream_body};
use serde_json::{Value, json};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn upstream() -> MockServer {
    let m = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&m)
        .await;
    m
}

fn bearer(req: &wiremock::Request) -> Option<String> {
    req.headers
        .get("authorization")
        .map(|v| v.to_str().unwrap().to_string())
}

async fn revision(h: &H) -> i64 {
    h.op_req(Method::GET, "/routes/r/backends")
        .await
        .json::<Value>()["revision"]
        .as_i64()
        .unwrap()
}

async fn switch(h: &H, to: &str) -> axum_test::TestResponse {
    let rev = revision(h).await;
    h.op_req(Method::POST, "/routes/r/switch")
        .add_header("if-match", &rev.to_string())
        .json(&json!({ "backend": to }))
        .await
}

/// Route `r` on upstream `a` with the agent bound to its own sealed key,
/// plus an inactive broker backend `pool` on `b` with a sealed broker key.
async fn scenario() -> (H, MockServer, MockServer) {
    let h = setup().await;
    let (a, b) = (upstream().await, upstream().await);
    h.put_model("r", upstream_body(&a.uri()))
        .await
        .assert_status_ok();
    h.grant(&["r"]).await;
    h.op_req(
        Method::PUT,
        &format!("/agents/{}/credentials/r/credential", h.pid),
    )
    .json(&json!({ "value": "agent-own-key" }))
    .await
    .assert_status_ok();
    h.op_req(Method::PUT, "/routes/r/backends/pool")
        .json(&json!({
            "upstream": b.uri(), "egress": "direct",
            "auth": { "kind": "none" }, "broker": {}
        }))
        .await
        .assert_status_ok();
    h.op_req(Method::PUT, "/routes/r/backends/pool/credential")
        .json(&json!({ "value": "broker-key-9" }))
        .await
        .assert_status_ok();
    (h, a, b)
}

#[tokio::test]
async fn switch_to_broker_and_back() {
    let (h, a, b) = scenario().await;
    h.call("r", "/v1/models").await.assert_status_ok();
    assert_eq!(
        bearer(&a.received_requests().await.unwrap()[0]).as_deref(),
        Some("Bearer agent-own-key")
    );

    switch(&h, "pool").await.assert_status_ok();
    let reg: Value = h.op_req(Method::GET, "/models/r").await.json();
    assert!(reg["broker"].is_object(), "active destination is a broker");
    let r = h.call("r", "/v1/models").await;
    assert_eq!(
        r.status_code(),
        403,
        "upstream binding never reaches the broker"
    );
    assert!(b.received_requests().await.unwrap().is_empty());

    h.bind("r", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    h.call("r", "/v1/models").await.assert_status_ok();
    let sent = &b.received_requests().await.unwrap()[0];
    assert_eq!(bearer(sent).as_deref(), Some("Bearer broker-key-9"));
    assert_eq!(
        sent.headers
            .get("x-locksmith-agent")
            .unwrap()
            .to_str()
            .unwrap(),
        h.pid
    );

    switch(&h, "primary").await.assert_status_ok();
    let reg: Value = h.op_req(Method::GET, "/models/r").await.json();
    assert!(reg["broker"].is_null());
    h.call("r", "/v1/models").await.assert_status_ok();
    let reqs = a.received_requests().await.unwrap();
    assert_eq!(
        bearer(reqs.last().unwrap()).as_deref(),
        Some("Bearer agent-own-key"),
        "upstream binding restored"
    );

    switch(&h, "pool").await.assert_status_ok();
    h.call("r", "/v1/models").await.assert_status_ok();
    assert_eq!(
        b.received_requests().await.unwrap().len(),
        2,
        "broker selection restored"
    );
}

#[tokio::test]
async fn backend_kind_change_clears_stash() {
    let (h, _a, _b) = scenario().await;
    switch(&h, "pool").await.assert_status_ok();
    h.bind("r", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    switch(&h, "primary").await.assert_status_ok();
    let stashed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM backend_bindings WHERE backend = 'pool'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(stashed, 1);
    h.op_req(Method::PUT, "/routes/r/backends/pool")
        .json(&json!({
            "upstream": "https://b.example", "egress": "direct",
            "auth": { "kind": "none" }
        }))
        .await
        .assert_status_ok();
    let stashed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM backend_bindings WHERE backend = 'pool'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(stashed, 0, "broker -> upstream discards the broker stash");
}

#[tokio::test]
async fn backend_credential_seals_without_echo() {
    let (h, _a, _b) = scenario().await;
    let before = revision(&h).await;
    let r = h
        .op_req(Method::PUT, "/routes/r/backends/pool/credential")
        .json(&json!({ "value": "rotated-key-1", "header": "X-Pool-Key" }))
        .await;
    r.assert_status_ok();
    assert!(!r.text().contains("rotated-key-1"));
    let reference = r.json::<Value>()["secret_ref"]
        .as_str()
        .unwrap()
        .to_string();
    let got: Value = h
        .op_req(Method::GET, "/routes/r/backends/pool")
        .await
        .json();
    assert_eq!(
        got["auth"],
        json!({ "kind": "stored_header", "header": "X-Pool-Key", "secret_ref": reference })
    );
    assert!(!got.to_string().contains("rotated-key-1"));
    assert_eq!(revision(&h).await, before + 1);
    let d = h.last_audit("route_backend_credential_set").await;
    assert_eq!(d["backend"], "pool");
    assert!(!d.to_string().contains("rotated-key-1"));
    let active = h
        .op_req(Method::PUT, "/routes/r/backends/primary/credential")
        .json(&json!({ "value": "x" }))
        .await;
    assert_eq!(active.status_code(), 409);
    assert_eq!(active.json::<Value>()["error"]["code"], "active_backend");
}

#[tokio::test]
async fn backend_broker_validated() {
    let (h, _a, _b) = scenario().await;
    for body in [
        json!({ "upstream": "https://c.example", "egress": "direct",
                "auth": { "kind": "bearer", "env_var": "K" }, "broker": {} }),
        json!({ "upstream": "https://c.example", "egress": "direct",
                "auth": { "kind": "none" }, "broker": { "health": { "path": "h" } } }),
        json!({ "upstream": "https://c.example", "egress": "direct",
                "auth": { "kind": "broker" } }),
    ] {
        let r = h
            .op_req(Method::PUT, "/routes/r/backends/c")
            .json(&body)
            .await;
        assert_eq!(r.status_code(), 400, "{body}");
        assert_eq!(
            r.json::<Value>()["error"]["code"],
            "invalid_broker",
            "{body}"
        );
    }
    let got: Value = h
        .op_req(Method::GET, "/routes/r/backends/pool")
        .await
        .json();
    assert_eq!(got["broker"]["identity_header"], "X-Locksmith-Agent");
}

#[tokio::test]
async fn backend_key_header_cannot_clash_with_identity_header() {
    let (h, _a, _b) = scenario().await;
    let r = h
        .op_req(Method::PUT, "/routes/r/backends/pool/credential")
        .json(&json!({ "value": "k", "header": "x-locksmith-agent" }))
        .await;
    assert_eq!(r.status_code(), 400);
    assert_eq!(r.json::<Value>()["error"]["code"], "invalid_broker");
}
