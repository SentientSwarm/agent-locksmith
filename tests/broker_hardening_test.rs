//! #159 — broker hardening: reserved header names are refused, an agent's
//! own identity header never reaches a broker, and the key edit paths keep
//! a key only for the destination it was sealed for.

#[path = "support/broker.rs"]
mod broker;

use axum::http::Method;
use broker::{H, broker_body, setup};
use serde_json::{Value, json};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Hop-by-hop and Locksmith-managed names.
const RESERVED: &[&str] = &[
    "Content-Length",
    "transfer-encoding",
    "connection",
    "te",
    "upgrade",
    "proxy-authorization",
    "openai-beta",
    "originator",
    "chatgpt-account-id",
];

async fn upstream() -> MockServer {
    let m = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&m)
        .await;
    m
}

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

async fn call_spoofed(h: &H) {
    h.agent
        .get("/api/pool/v1/models")
        .add_header("authorization", &h.agent_bearer)
        .add_header("x-locksmith-agent", "spoofed-agent")
        .await
        .assert_status_ok();
}

fn values(req: &wiremock::Request, name: &str) -> Vec<String> {
    req.headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

fn code(r: &axum_test::TestResponse) -> String {
    let v: Value = r.json();
    v["error"]["code"].as_str().unwrap_or_default().to_string()
}

#[tokio::test]
async fn disabled_identity_still_strips_the_agents_copy() {
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({ "identity_header": null })).await;
    call_spoofed(&h).await;
    let reqs = m.received_requests().await.unwrap();
    assert!(values(&reqs[0], "x-locksmith-agent").is_empty());
}

#[tokio::test]
async fn custom_identity_strips_the_default_name() {
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({ "identity_header": "X-Pool-Agent" })).await;
    call_spoofed(&h).await;
    let reqs = m.received_requests().await.unwrap();
    assert!(values(&reqs[0], "x-locksmith-agent").is_empty());
    assert_eq!(
        values(&reqs[0], "x-pool-agent"),
        std::slice::from_ref(&h.pid)
    );
}

#[tokio::test]
async fn reserved_identity_header_is_refused() {
    let h = setup().await;
    for name in RESERVED.iter().chain(&["x-api-key"]) {
        let mut body = broker_body("https://pool.example", json!({ "identity_header": name }));
        body["auth"] = json!({ "kind": "none" });
        let r = h.put_model("pool", body).await;
        assert_eq!(r.status_code(), 400, "{name}");
        assert_eq!(code(&r), "invalid_broker", "{name}");
    }
}

#[tokio::test]
async fn reserved_credential_header_is_refused() {
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({})).await;
    h.op_req(Method::PUT, "/routes/pool/backends/b")
        .json(
            &json!({ "upstream": "https://b.example", "egress": "direct",
                       "auth": { "kind": "none" }, "broker": {} }),
        )
        .await
        .assert_status_ok();
    h.put_model(
        "plain",
        json!({ "upstream": "https://p.example",
                                 "auth": { "kind": "none" }, "egress": "direct" }),
    )
    .await
    .assert_status_ok();
    h.grant(&["pool", "plain"]).await;
    for name in RESERVED {
        let body = json!({ "value": "k", "header": name });
        let route = h
            .op_req(Method::PUT, "/models/pool/credential")
            .json(&body)
            .await;
        assert_eq!(route.status_code(), 400, "route {name}");
        let backend = h
            .op_req(Method::PUT, "/routes/pool/backends/b/credential")
            .json(&body)
            .await;
        assert_eq!(backend.status_code(), 400, "backend {name}");
        let agent = h
            .op_req(
                Method::PUT,
                &format!("/agents/{}/credentials/plain/credential", h.pid),
            )
            .json(&body)
            .await;
        assert_eq!(agent.status_code(), 400, "agent {name}");
    }
    // An ordinary key header still works on every path.
    let ok = json!({ "value": "k", "header": "X-Api-Key" });
    h.op_req(Method::PUT, "/models/pool/credential")
        .json(&ok)
        .await
        .assert_status_ok();
}

const FAR_FUTURE: i64 = i64::MAX / 2;

/// A broker route `pool` on `m` probing `/healthz` (expecting `expect`).
async fn probed_route(h: &H, m: &MockServer, expect: u16) {
    let mut body = broker_body(
        &m.uri(),
        json!({ "health": { "path": "/healthz", "expect_status": expect } }),
    );
    body["auth"] = json!({ "kind": "none" });
    h.put_model("pool", body).await.assert_status_ok();
    h.seal("pool", "broker-key-1").await;
    h.grant(&["pool"]).await;
    h.bind("pool", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
}

async fn api_hits(m: &MockServer) -> usize {
    m.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() != "/healthz")
        .count()
}

async fn broker_logs(h: &H, event: &str) -> Vec<String> {
    for _ in 0..100 {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT COALESCE(fields, '') FROM operational_logs \
             WHERE component = 'broker' AND event = ?",
        )
        .bind(event)
        .fetch_all(&h.pool)
        .await
        .unwrap();
        if !rows.is_empty() {
            return rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Vec::new()
}

/// Item 3 — a key that cannot be materialized is reported as the key, not
/// as the broker being down, and the request fails on the key.
#[tokio::test]
async fn unusable_key_is_not_reported_as_broker_down() {
    let h = setup().await;
    let m = upstream().await;
    probed_route(&h, &m, 200).await;
    sqlx::query("UPDATE credential_secrets SET tombstoned_at = unixepoch()")
        .execute(&h.pool)
        .await
        .unwrap();
    h.prober.tick_at(FAR_FUTURE).await;
    assert_eq!(h.health.get("pool"), None, "no health recorded");
    let logs = broker_logs(&h, "broker_key_unresolved").await;
    assert_eq!(logs.len(), 1);
    assert!(logs[0].contains("pool") && !logs[0].contains("broker-key-1"));
    assert!(broker_logs(&h, "broker_down").await.is_empty());
    let r = h.call("pool", "/v1/models").await;
    assert_eq!(r.status_code(), 503);
    assert_eq!(code(&r), "credential_unresolved");
    assert_eq!(api_hits(&m).await, 0);
}

/// Item 4 / M3 — the probe does not follow redirects: a redirect is the
/// result, and a 3xx `expect_status` can match.
#[tokio::test]
async fn probe_does_not_follow_redirects() {
    use agent_locksmith::registrations::broker_health::HealthStatus;
    use wiremock::matchers::path;
    let m = MockServer::start().await;
    Mock::given(path("/healthz"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/ok"))
        .mount(&m)
        .await;
    Mock::given(path("/ok"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&m)
        .await;
    let h = setup().await;
    probed_route(&h, &m, 200).await;
    h.prober.tick_at(FAR_FUTURE).await;
    let s = h.health.get("pool").unwrap();
    assert_eq!((s.status, s.http_status), (HealthStatus::Down, Some(302)));
    let followed = m
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|r| r.url.path() == "/ok");
    assert!(!followed, "redirect was followed");

    let h = setup().await;
    probed_route(&h, &m, 302).await;
    h.prober.tick_at(FAR_FUTURE).await;
    assert_eq!(h.health.get("pool").unwrap().status, HealthStatus::Up);
}

/// Item 6 — an `op://` broker key that is not resolved fails closed with
/// zero dispatch.
#[tokio::test]
async fn unresolved_op_key_never_dispatches() {
    let h = setup().await;
    let m = upstream().await;
    let mut body = broker_body(&m.uri(), json!({}));
    body["auth"] = json!({ "kind": "op_bearer", "reference": "op://vault/pool/key" });
    h.put_model("pool", body).await.assert_status_ok();
    h.grant(&["pool"]).await;
    h.bind("pool", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    let r = h.call("pool", "/v1/models").await;
    assert_eq!(r.status_code(), 503);
    assert_eq!(code(&r), "credential_unresolved");
    assert_eq!(api_hits(&m).await, 0);
}

/// Item 6 — one hanging broker does not hold another's probe result past
/// a single probe timeout.
#[tokio::test]
async fn hanging_broker_does_not_stall_another() {
    use agent_locksmith::registrations::broker_health::{HealthStatus, PROBE_TIMEOUT};
    use wiremock::matchers::path;
    let slow = MockServer::start().await;
    Mock::given(path("/healthz"))
        .respond_with(ResponseTemplate::new(200).set_delay(PROBE_TIMEOUT * 3))
        .mount(&slow)
        .await;
    let fast = upstream().await;
    Mock::given(path("/healthz"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&fast)
        .await;
    let h = setup().await;
    for (name, m) in [("slow", &slow), ("fast", &fast)] {
        let mut body = broker_body(&m.uri(), json!({ "health": { "path": "/healthz" } }));
        body["auth"] = json!({ "kind": "none" });
        h.put_model(name, body).await.assert_status_ok();
        h.seal(name, "broker-key-1").await;
    }
    let started = std::time::Instant::now();
    h.prober.tick_at(FAR_FUTURE).await;
    assert!(
        started.elapsed() < PROBE_TIMEOUT * 2,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(h.health.get("fast").unwrap().status, HealthStatus::Up);
    assert_eq!(h.health.get("slow").unwrap().status, HealthStatus::Down);
}

/// Item 7 — a repeated attribution header is ambiguous, so it is flagged
/// rather than recorded as its first value.
#[tokio::test]
async fn repeated_attribution_header_is_flagged() {
    let m = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("x-pool-account", "acct-a")
                .append_header("x-pool-account", "acct-b"),
        )
        .mount(&m)
        .await;
    let h = setup().await;
    broker_route(
        &h,
        &m,
        json!({ "attribution": { "header": "X-Pool-Account" } }),
    )
    .await;
    h.call("pool", "/v1/models").await.assert_status_ok();
    let d = h.last_audit("proxy_request").await;
    assert_eq!(d["broker_account_invalid"], true, "{d}");
    assert!(d.get("broker_account").is_none());
}

/// M5 — a broker that is down does not mask a broken selection: the
/// selection failure is reported.
#[tokio::test]
async fn broken_selection_is_reported_before_broker_health() {
    use wiremock::matchers::path;
    let m = upstream().await;
    Mock::given(path("/healthz"))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&m)
        .await;
    let h = setup().await;
    probed_route(&h, &m, 200).await;
    h.prober.tick_at(FAR_FUTURE).await;
    // A selection row that is not `broker` (e.g. from before brokers).
    sqlx::query("UPDATE agent_credential_overrides SET auth_spec = '{\"kind\":\"none\"}'")
        .execute(&h.pool)
        .await
        .unwrap();
    let r = h.call("pool", "/v1/models").await;
    assert_ne!(code(&r), "backend_unavailable", "{}", r.text());
    assert_eq!(api_hits(&m).await, 0);
}

async fn route_auth(h: &H, name: &str) -> Value {
    h.op_req(Method::GET, &format!("/models/{name}"))
        .await
        .json::<Value>()["auth"]
        .clone()
}

/// M4 — a broker `put` without `auth` keeps the key only for the same
/// destination; moving it needs explicit auth.
#[tokio::test]
async fn kept_key_does_not_follow_a_repoint() {
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({})).await;
    let sealed = route_auth(&h, "pool").await;
    let mut body = broker_body("https://elsewhere.example", json!({}));
    body.as_object_mut().unwrap().remove("auth");
    let r = h.put_model("pool", body).await;
    assert_eq!(r.status_code(), 400);
    assert_eq!(code(&r), "invalid_broker");
    assert_eq!(route_auth(&h, "pool").await, sealed);
}

/// M2 — a keep-key write prepared before a rotation does not undo it.
#[tokio::test]
async fn kept_key_write_does_not_undo_a_rotation() {
    use agent_locksmith::registrations::{RegistrationError, RegistrationRepository};
    let h = setup().await;
    let m = upstream().await;
    broker_route(&h, &m, json!({})).await;
    let repo = RegistrationRepository::new(h.pool.clone());
    let stale = repo.get("pool").await.unwrap().unwrap();
    h.seal("pool", "broker-key-2").await;
    let rotated = route_auth(&h, "pool").await;
    assert!(matches!(
        repo.upsert_keeping_key(&stale).await,
        Err(RegistrationError::BrokerKeyChanged)
    ));
    assert_eq!(route_auth(&h, "pool").await, rotated);
    // Unchanged since it was read: the write lands.
    let fresh = repo.get("pool").await.unwrap().unwrap();
    repo.upsert_keeping_key(&fresh).await.unwrap();
}

/// M6 — on an ordinary route, `header` sends the sealed key in that header
/// instead of as a bearer token.
#[tokio::test]
async fn credential_header_on_a_plain_route() {
    let h = setup().await;
    let m = upstream().await;
    h.put_model(
        "plain",
        json!({ "upstream": m.uri(), "auth": { "kind": "none" }, "egress": "direct" }),
    )
    .await
    .assert_status_ok();
    h.op_req(Method::PUT, "/models/plain/credential")
        .json(&json!({ "value": "plain-key", "header": "X-Api-Key" }))
        .await
        .assert_status_ok();
    let auth = route_auth(&h, "plain").await;
    assert_eq!(auth["kind"], "stored_header");
    assert_eq!(auth["header"], "X-Api-Key");
}
