//! AGENT-266 — per-agent, per-route rate limits.
//!
//! A route default applies to each agent separately; an agent row
//! overrides it. Over the limit the proxy answers 429 `rate_limited` with
//! `Retry-After`, before anything is sent upstream. Limits change live
//! through the admin API.

#[path = "support/broker.rs"]
mod broker;

use agent_locksmith::repo::AgentRepository;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use broker::{H, setup, upstream_body};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn route(h: &H) -> MockServer {
    let up = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&up)
        .await;
    h.put_model("up", upstream_body(&up.uri()))
        .await
        .assert_status_ok();
    h.grant(&["up"]).await;
    h.bind("up", json!({ "kind": "none" }))
        .await
        .assert_status_ok();
    up
}

/// A second agent granted the same route; returns its bearer.
async fn second_agent(h: &H) -> String {
    let (pid, secret) = AgentRepository::new(h.pool.clone())
        .create("agent-2", None, None, None, None, None)
        .await
        .unwrap();
    h.op_req(Method::PATCH, &format!("/agents/{pid}"))
        .json(&json!({ "allowlist": ["up"] }))
        .await
        .assert_status_no_content();
    h.op_req(Method::PUT, &format!("/agents/{pid}/credentials/up"))
        .json(&json!({ "auth_spec": { "kind": "none" } }))
        .await
        .assert_status_ok();
    format!("Bearer lk_{pid}.{}", secret.expose_secret())
}

async fn set(h: &H, body: Value) {
    h.op_req(Method::PUT, "/rate-limits/up")
        .json(&body)
        .await
        .assert_status_ok();
}

async fn call_as(h: &H, bearer: &str) -> axum_test::TestResponse {
    h.agent
        .get("/api/up/x")
        .add_header("authorization", bearer)
        .await
}

async fn count(h: &H, event: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event = ?")
        .bind(event)
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn route_default_limits_the_third_request_in_a_minute() {
    let h = setup().await;
    let up = route(&h).await;
    set(&h, json!({ "requests_per_minute": 2 })).await;
    assert_eq!(count(&h, "rate_limit_set").await, 1);
    for _ in 0..2 {
        h.call("up", "/x").await.assert_status_ok();
    }
    let r = h.call("up", "/x").await;
    assert_eq!(r.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.json::<Value>()["error"]["code"], "rate_limited");
    let retry: u64 = r.header("retry-after").to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry), "Retry-After {retry}");
    assert_eq!(up.received_requests().await.unwrap().len(), 2);
    assert_eq!(count(&h, "rate_limited").await, 1);
}

#[tokio::test]
async fn limit_is_per_agent() {
    let h = setup().await;
    let _up = route(&h).await;
    let b = second_agent(&h).await;
    set(&h, json!({ "requests_per_minute": 1 })).await;
    h.call("up", "/x").await.assert_status_ok();
    assert_eq!(
        h.call("up", "/x").await.status_code(),
        StatusCode::TOO_MANY_REQUESTS
    );
    call_as(&h, &b).await.assert_status_ok();
}

#[tokio::test]
async fn agent_override_raises_its_limit() {
    let h = setup().await;
    let _up = route(&h).await;
    let b = second_agent(&h).await;
    set(&h, json!({ "requests_per_minute": 1 })).await;
    set(&h, json!({ "requests_per_minute": 3, "agent": h.pid })).await;
    for _ in 0..3 {
        h.call("up", "/x").await.assert_status_ok();
    }
    call_as(&h, &b).await.assert_status_ok();
    assert_eq!(
        call_as(&h, &b).await.status_code(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let list: Value = h.op_req(Method::GET, "/rate-limits").await.json();
    assert_eq!(list["rate_limits"].as_array().unwrap().len(), 2, "{list}");
}

#[tokio::test]
async fn deleting_the_limit_restores_unlimited() {
    let h = setup().await;
    let _up = route(&h).await;
    set(&h, json!({ "requests_per_minute": 1 })).await;
    h.call("up", "/x").await.assert_status_ok();
    assert_eq!(
        h.call("up", "/x").await.status_code(),
        StatusCode::TOO_MANY_REQUESTS
    );
    h.op_req(Method::DELETE, "/rate-limits/up")
        .await
        .assert_status_no_content();
    assert_eq!(count(&h, "rate_limit_deleted").await, 1);
    for _ in 0..3 {
        h.call("up", "/x").await.assert_status_ok();
    }
}

#[tokio::test]
async fn concurrency_permit_is_held_until_the_body_is_dropped() {
    let h = setup().await;
    let _up = route(&h).await;
    set(
        &h,
        json!({ "requests_per_minute": 100, "max_concurrent": 1 }),
    )
    .await;
    let req = || {
        Request::builder()
            .uri("/api/up/x")
            .header("authorization", &h.agent_bearer)
            .body(Body::empty())
            .unwrap()
    };
    let first = h.agent_app.clone().oneshot(req()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    // The first body is not yet read: its permit is still held.
    let second = h.agent_app.clone().oneshot(req()).await.unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    drop(first);
    let third = h.agent_app.clone().oneshot(req()).await.unwrap();
    assert_eq!(third.status(), StatusCode::OK);
}

#[tokio::test]
async fn invalid_limits_are_rejected() {
    let h = setup().await;
    let _up = route(&h).await;
    for body in [
        json!({ "requests_per_minute": 0 }),
        json!({ "requests_per_minute": 5, "max_concurrent": 0 }),
        json!({ "requests_per_minute": 5, "agent": "no-such-agent" }),
    ] {
        let r = h.op_req(Method::PUT, "/rate-limits/up").json(&body).await;
        assert!(
            r.status_code().is_client_error(),
            "{body} → {}",
            r.status_code()
        );
    }
    h.call("up", "/x").await.assert_status_ok();
}
