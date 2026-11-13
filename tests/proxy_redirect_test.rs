//! AGENT-242 — the proxy never follows an upstream redirect. A followed
//! cross-host redirect would carry Locksmith's injected key header (custom
//! names such as `x-api-key` survive reqwest's own stripping) to a host
//! the route never named. The agent receives the 3xx instead.

#[path = "support/registered_legacy.rs"]
mod registered;
use agent_locksmith::config::parse_config_str;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn harness(upstream: &str) -> registered::Fixture {
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "keyed"
    description: "Custom key header"
    upstream: "{upstream}"
    auth:
      header: "x-api-key"
      value: "route-key"
    timeout_seconds: 15
"#
    );
    let mut h = registered::setup(parse_config_str(&yaml).unwrap()).await;
    h.server.add_header("authorization", &h.bearer);
    h
}

#[tokio::test]
async fn cross_host_redirect_is_returned_not_followed() {
    let elsewhere = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&elsewhere)
        .await;
    let upstream = MockServer::start().await;
    let target = format!("{}/collect", elsewhere.uri());
    Mock::given(path("/go"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", target.as_str()))
        .mount(&upstream)
        .await;

    let h = harness(&upstream.uri()).await;
    let resp = h.server.get("/api/keyed/go").await;

    assert_eq!(resp.status_code(), 302);
    assert_eq!(resp.headers()["location"], target.as_str());
    let leaked = elsewhere.received_requests().await.unwrap();
    assert!(leaked.is_empty(), "redirect was followed to another host");
}

#[tokio::test]
async fn same_upstream_redirect_points_back_at_locksmith() {
    let upstream = MockServer::start().await;
    let next = format!("{}/next", upstream.uri());
    Mock::given(path("/go"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", next.as_str()))
        .mount(&upstream)
        .await;
    Mock::given(path("/next"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let h = harness(&upstream.uri()).await;
    let resp = h
        .server
        .get("/api/keyed/go")
        .add_header("host", "locksmith.test:9200")
        .await;

    assert_eq!(resp.status_code(), 307);
    assert_eq!(
        resp.headers()["location"],
        "http://locksmith.test:9200/api/keyed/next"
    );
    let hits = upstream.received_requests().await.unwrap();
    assert!(hits.iter().all(|r| r.url.path() == "/go"), "followed");
}
