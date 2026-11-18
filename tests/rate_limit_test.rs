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

/// AGENT-272: the limit is checked before any credential is resolved, so
/// a limited route whose credential cannot be resolved answers 429, not
/// 503, once the agent is over its limit.
#[tokio::test]
async fn the_limit_is_checked_before_the_credential() {
    let h = setup().await;
    let m = MockServer::start().await;
    let mut body = broker::broker_body(&m.uri(), json!({}));
    body["auth"] = json!({ "kind": "none" });
    h.put_model("up", body).await.assert_status_ok();
    h.seal("up", "broker-key-1").await;
    h.grant(&["up"]).await;
    h.bind("up", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    // The sealed key is gone by the time a request resolves it.
    sqlx::query("UPDATE credential_secrets SET tombstoned_at = unixepoch()")
        .execute(&h.pool)
        .await
        .unwrap();
    set(&h, json!({ "requests_per_minute": 1 })).await;
    let first = h.call("up", "/x").await;
    assert_eq!(
        first.json::<Value>()["error"]["code"],
        "credential_unresolved"
    );
    let second = h.call("up", "/x").await;
    assert_eq!(second.status_code(), StatusCode::TOO_MANY_REQUESTS);
    assert!(m.received_requests().await.unwrap().is_empty());
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

#[tokio::test]
async fn limits_are_refused_on_routes_the_proxy_does_not_serve() {
    // AGENT-272: only `/api/*` enforces limits, so a limit on a native MCP
    // or infra registration would be listed and audited but never applied.
    let h = setup().await;
    h.op_req(Method::PUT, "/tools/native")
        .json(&json!({
            "upstream": "https://example.com/mcp", "auth": { "kind": "none" },
            "egress": "direct", "protocol": "mcp_streamable_http",
            "mcp": { "protocol_version": "2025-11-25" }
        }))
        .await
        .assert_status_ok();
    h.op_req(Method::PUT, "/infra/scanner")
        .json(&upstream_body("https://example.com"))
        .await
        .assert_status_ok();
    for route in ["native", "scanner"] {
        let r = h
            .op_req(Method::PUT, &format!("/rate-limits/{route}"))
            .json(&json!({ "requests_per_minute": 5 }))
            .await;
        assert_eq!(r.status_code(), StatusCode::BAD_REQUEST, "{route}");
        assert_eq!(
            r.json::<Value>()["error"]["code"],
            "route_not_limitable",
            "{route}"
        );
    }
    assert_eq!(count(&h, "rate_limit_set").await, 0);
}

/// AGENT-272: a stored limit whose route is gone (or is no longer an HTTP
/// model or tool route) stays listed but says it is not enforced.
#[tokio::test]
async fn list_marks_limits_whose_route_is_gone() {
    let h = setup().await;
    let _up = route(&h).await;
    set(&h, json!({ "requests_per_minute": 5 })).await;
    let list: Value = h.op_req(Method::GET, "/rate-limits").await.json();
    assert_eq!(list["rate_limits"][0]["enforced"], true, "{list}");
    h.op_req(Method::DELETE, "/models/up")
        .await
        .assert_status_no_content();
    let list: Value = h.op_req(Method::GET, "/rate-limits").await.json();
    assert_eq!(list["rate_limits"][0]["route"], "up", "{list}");
    assert_eq!(list["rate_limits"][0]["enforced"], false, "{list}");
}

async fn enforced(h: &H) -> Value {
    let list: Value = h.op_req(Method::GET, "/rate-limits").await.json();
    list["rate_limits"][0]["enforced"].clone()
}

/// AGENT-272: admission refuses a disabled route before the limiter runs,
/// so its limit is listed as not enforced until the route is enabled.
#[tokio::test]
async fn list_marks_a_disabled_route_not_enforced() {
    let h = setup().await;
    let _up = route(&h).await;
    set(&h, json!({ "requests_per_minute": 5 })).await;
    let regs = agent_locksmith::registrations::RegistrationRepository::new(h.pool.clone());
    regs.set_disabled("up", true).await.unwrap();
    assert_eq!(enforced(&h).await, false);
    regs.set_disabled("up", false).await.unwrap();
    assert_eq!(enforced(&h).await, true);
}

/// AGENT-272: a limit follows its route name. Recreated as a native MCP
/// route it is not enforced; recreated as HTTP it limits again.
#[tokio::test]
async fn a_limit_follows_its_route_through_recreation() {
    let h = setup().await;
    let _up = route(&h).await;
    set(&h, json!({ "requests_per_minute": 1 })).await;
    h.op_req(Method::DELETE, "/models/up")
        .await
        .assert_status_no_content();
    h.op_req(Method::PUT, "/tools/up")
        .json(&json!({
            "upstream": "https://example.com/mcp", "auth": { "kind": "none" },
            "egress": "direct", "protocol": "mcp_streamable_http",
            "mcp": { "protocol_version": "2025-11-25" }
        }))
        .await
        .assert_status_ok();
    assert_eq!(enforced(&h).await, false);
    h.op_req(Method::DELETE, "/tools/up")
        .await
        .assert_status_no_content();
    let _up = route(&h).await;
    assert_eq!(enforced(&h).await, true);
    h.call("up", "/x").await.assert_status_ok();
    assert_eq!(
        h.call("up", "/x").await.status_code(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// AGENT-272: a hammering agent writes one `rate_limited` row a minute,
/// not one per refusal; the next row counts the refusals in between.
#[tokio::test]
async fn refusals_write_one_audit_row_a_minute() {
    let h = setup().await;
    let _up = route(&h).await;
    set(&h, json!({ "requests_per_minute": 1 })).await;
    h.call("up", "/x").await.assert_status_ok();
    for _ in 0..5 {
        assert_eq!(
            h.call("up", "/x").await.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(count(&h, "rate_limited").await, 1);
    assert_eq!(h.last_audit("rate_limited").await["suppressed"], 0);
}

/// AGENT-272: the set and delete audit rows carry the limit they replaced.
#[tokio::test]
async fn audit_rows_carry_the_previous_limit() {
    let h = setup().await;
    let _up = route(&h).await;
    set(&h, json!({ "requests_per_minute": 2 })).await;
    assert!(
        h.last_audit("rate_limit_set")
            .await
            .get("previous")
            .is_none()
    );
    set(&h, json!({ "requests_per_minute": 3, "max_concurrent": 1 })).await;
    let previous = &h.last_audit("rate_limit_set").await["previous"];
    assert_eq!(previous["requests_per_minute"], 2);
    h.op_req(Method::DELETE, "/rate-limits/up")
        .await
        .assert_status_no_content();
    let previous = &h.last_audit("rate_limit_deleted").await["previous"];
    assert_eq!(previous["requests_per_minute"], 3);
    assert_eq!(previous["max_concurrent"], 1);
}

/// AGENT-272: a limit that is stored but cannot be loaded into the proxy
/// answers 503 `rate_limits_not_applied`, and the row stays stored.
#[tokio::test]
async fn a_stored_limit_that_cannot_load_says_so() {
    let h = setup().await;
    let _up = route(&h).await;
    // Another route's row the loader cannot read (over u32).
    sqlx::query(
        "INSERT INTO rate_limits (route, agent_id, requests_per_minute, updated_at) \
         VALUES ('other', NULL, 5000000000, 0)",
    )
    .execute(&h.pool)
    .await
    .unwrap();
    let r = h
        .op_req(Method::PUT, "/rate-limits/up")
        .json(&json!({ "requests_per_minute": 2 }))
        .await;
    assert_eq!(r.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        r.json::<Value>()["error"]["code"],
        "rate_limits_not_applied"
    );
    let stored: i64 =
        sqlx::query_scalar("SELECT requests_per_minute FROM rate_limits WHERE route = 'up'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(stored, 2);
}
