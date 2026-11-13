//! Brokered routes phase 3 — broker health. A probe sends the broker key;
//! a broker that fails it answers 503 backend_unavailable without
//! dispatch, readiness reports counts only, and transitions are logged.

#[path = "support/broker.rs"]
mod broker;

use agent_locksmith::registrations::broker_health::HealthStatus;
use broker::{H, broker_body, setup};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const FAR_FUTURE: i64 = i64::MAX / 2;
/// The default probe interval: one step makes every probe due again.
const STEP: i64 = 30;

/// `/healthz` answers 200 for the first `up` probes, then 500.
async fn broker_server(up: u64) -> MockServer {
    let m = MockServer::start().await;
    if up > 0 {
        Mock::given(path("/healthz"))
            .respond_with(ResponseTemplate::new(200))
            .up_to_n_times(up)
            .with_priority(1)
            .mount(&m)
            .await;
    }
    Mock::given(path("/healthz"))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(2)
        .mount(&m)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .with_priority(3)
        .mount(&m)
        .await;
    m
}

async fn route(h: &H, m: &MockServer) {
    let mut body = broker_body(&m.uri(), json!({ "health": { "path": "/healthz" } }));
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

#[tokio::test]
async fn probe_up_then_down_refuses_without_dispatch() {
    let h = setup().await;
    let m = broker_server(1).await;
    route(&h, &m).await;
    h.prober.tick_at(FAR_FUTURE).await;
    assert_eq!(h.health.get("pool").unwrap().status, HealthStatus::Up);
    let probe = &m.received_requests().await.unwrap()[0];
    assert_eq!(
        probe
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer broker-key-1",
        "the probe carries the broker key"
    );
    h.call("pool", "/v1/models").await.assert_status_ok();

    h.prober.tick_at(FAR_FUTURE + STEP).await;
    assert_eq!(h.health.get("pool").unwrap().status, HealthStatus::Down);
    let r = h.call("pool", "/v1/models").await;
    assert_eq!(r.status_code(), 503);
    assert_eq!(r.json::<Value>()["error"]["code"], "backend_unavailable");
    assert_eq!(api_hits(&m).await, 1, "no dispatch while down");
}

#[tokio::test]
async fn unknown_is_admitted() {
    let h = setup().await;
    let m = broker_server(0).await;
    route(&h, &m).await;
    assert!(h.health.get("pool").is_none());
    h.call("pool", "/v1/models").await.assert_status_ok();
}

#[tokio::test]
async fn hanging_health_marks_down_within_timeout() {
    let h = setup().await;
    let m = MockServer::start().await;
    Mock::given(path("/healthz"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&m)
        .await;
    route(&h, &m).await;
    let started = Instant::now();
    h.prober.tick_at(FAR_FUTURE).await;
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(h.health.get("pool").unwrap().status, HealthStatus::Down);
}

#[tokio::test]
async fn readyz_reports_counts_only() {
    let h = setup().await;
    let m = broker_server(1).await;
    route(&h, &m).await;
    let before: Value = h.agent.get("/readyz").await.json();
    assert_eq!(
        before["brokers"],
        json!({ "up": 0, "down": 0, "unknown": 1 })
    );
    h.prober.tick_at(FAR_FUTURE).await;
    let r = h.agent.get("/readyz").await;
    r.assert_status_ok();
    assert_eq!(
        r.json::<Value>()["brokers"],
        json!({ "up": 1, "down": 0, "unknown": 0 })
    );
    assert!(!r.text().contains("pool"), "no route names on /readyz");
    h.prober.tick_at(FAR_FUTURE + STEP).await;
    let r = h.agent.get("/readyz").await;
    r.assert_status_ok();
    assert_eq!(
        r.json::<Value>()["brokers"]["down"],
        1,
        "a down broker stays ready"
    );
}

#[tokio::test]
async fn transition_logged_once() {
    let h = setup().await;
    let m = broker_server(1).await;
    route(&h, &m).await;
    for t in 0..3 {
        h.prober.tick_at(FAR_FUTURE + STEP * t).await;
    }
    // The operational log drains asynchronously: wait for the warning,
    // then a little longer so a duplicate would also have landed.
    let query = "SELECT level, event, COALESCE(fields, '') FROM operational_logs \
                 WHERE component = 'broker'";
    for _ in 0..100 {
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM operational_logs WHERE component = 'broker'")
                .fetch_one(&h.pool)
                .await
                .unwrap();
        if n > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let rows: Vec<(String, String, String)> =
        sqlx::query_as(query).fetch_all(&h.pool).await.unwrap();
    let downs: Vec<_> = rows.iter().filter(|r| r.1 == "broker_down").collect();
    assert_eq!(downs.len(), 1, "{rows:?}");
    assert_eq!(downs[0].0, "warn");
    assert!(downs[0].2.contains("pool"));
    assert!(!downs[0].2.contains("broker-key-1"));
}

#[tokio::test]
async fn admin_get_shows_route_health() {
    let h = setup().await;
    let m = broker_server(1).await;
    route(&h, &m).await;
    let get = |path: &'static str| {
        let h = &h;
        async move {
            h.op_req(axum::http::Method::GET, path)
                .await
                .json::<Value>()
        }
    };
    assert!(get("/models/pool").await["health"].is_null(), "unknown");
    h.prober.tick_at(FAR_FUTURE).await;
    let got = get("/models/pool").await;
    assert_eq!(got["health"]["status"], "up");
    assert_eq!(got["health"]["http_status"], 200);
    assert_eq!(got["health"]["checked_at"], FAR_FUTURE);
    h.prober.tick_at(FAR_FUTURE + STEP).await;
    assert_eq!(get("/models/pool").await["health"]["status"], "down");
    let list = get("/models").await;
    let row = list["models"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "pool")
        .unwrap()
        .clone();
    assert_eq!(row["health"]["status"], "down");
    assert!(!list.to_string().contains("broker-key-1"));
}

/// `/healthz` always 500; every other GET 200.
async fn failing_broker() -> MockServer {
    broker_server(0).await
}

fn stored(sref: &str) -> Value {
    json!({ "kind": "stored_bearer", "secret_ref": sref })
}

#[tokio::test]
async fn removed_probe_admits_and_forgets() {
    let h = setup().await;
    let m = failing_broker().await;
    let mut body = broker_body(&m.uri(), json!({ "health": { "path": "/healthz" } }));
    body["auth"] = json!({ "kind": "none" });
    h.put_model("pool", body).await.assert_status_ok();
    let sref = h.seal("pool", "broker-key-1").await;
    h.grant(&["pool"]).await;
    h.bind("pool", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    h.prober.tick_at(FAR_FUTURE).await;
    assert_eq!(h.call("pool", "/v1/models").await.status_code(), 503);

    let mut body = broker_body(&m.uri(), json!({}));
    body["auth"] = stored(&sref);
    h.put_model("pool", body).await.assert_status_ok();
    h.call("pool", "/v1/models").await.assert_status_ok();
    h.prober.tick_at(FAR_FUTURE + STEP).await;
    assert!(
        h.health.get("pool").is_none(),
        "unprobed routes are forgotten"
    );
}

#[tokio::test]
async fn repointed_broker_is_probed_again() {
    let h = setup().await;
    let bad = failing_broker().await;
    let good = broker_server(10).await;
    let spec = json!({ "health": { "path": "/healthz", "interval_seconds": 3600 } });
    let mut body = broker_body(&bad.uri(), spec.clone());
    body["auth"] = json!({ "kind": "none" });
    h.put_model("pool", body).await.assert_status_ok();
    let sref = h.seal("pool", "broker-key-1").await;
    h.prober.tick_at(FAR_FUTURE).await;
    assert_eq!(h.health.get("pool").unwrap().status, HealthStatus::Down);

    let mut body = broker_body(&good.uri(), spec);
    body["auth"] = stored(&sref);
    h.put_model("pool", body).await.assert_status_ok();
    h.grant(&["pool"]).await;
    h.bind("pool", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    h.call("pool", "/v1/models").await.assert_status_ok();
    let got: Value = h
        .op_req(axum::http::Method::GET, "/models/pool")
        .await
        .json();
    assert!(
        got["health"].is_null(),
        "a result for the old destination is not shown"
    );
    h.prober.tick_at(FAR_FUTURE + 1).await;
    assert!(
        !good.received_requests().await.unwrap().is_empty(),
        "a new destination is probed on the next tick"
    );
    assert_eq!(h.health.get("pool").unwrap().status, HealthStatus::Up);
}

#[tokio::test]
async fn failover_to_a_broker_backend_is_admitted() {
    let h = setup().await;
    let bad = failing_broker().await;
    let good = broker_server(10).await;
    route(&h, &bad).await;
    h.prober.tick_at(FAR_FUTURE).await;
    assert_eq!(h.call("pool", "/v1/models").await.status_code(), 503);

    h.op_req(axum::http::Method::PUT, "/routes/pool/backends/b")
        .json(&json!({
            "upstream": good.uri(), "egress": "direct",
            "auth": { "kind": "none" }, "broker": {}
        }))
        .await
        .assert_status_ok();
    h.op_req(
        axum::http::Method::PUT,
        "/routes/pool/backends/b/credential",
    )
    .json(&json!({ "value": "broker-key-2" }))
    .await
    .assert_status_ok();
    let rev = h
        .op_req(axum::http::Method::GET, "/routes/pool/backends")
        .await
        .json::<Value>()["revision"]
        .as_i64()
        .unwrap();
    h.op_req(axum::http::Method::POST, "/routes/pool/switch")
        .add_header("if-match", &rev.to_string())
        .json(&json!({ "backend": "b" }))
        .await
        .assert_status_ok();
    h.bind("pool", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    h.call("pool", "/v1/models").await.assert_status_ok();
}
