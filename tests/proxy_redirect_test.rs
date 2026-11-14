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
    harness_with(upstream, "").await
}

async fn harness_with(upstream: &str, extra: &str) -> registered::Fixture {
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
{extra}"#
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

/// A relative `Location` was resolved by the client while redirects were
/// followed. Returned as is, it would resolve against Locksmith instead
/// of the route, so it is resolved against the upstream request first.
#[tokio::test]
async fn relative_redirect_is_resolved_onto_the_route() {
    let upstream = MockServer::start().await;
    Mock::given(path("/v1/go"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/v1/next?a=1"))
        .mount(&upstream)
        .await;
    Mock::given(path("/v1/dir/go"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "sibling"))
        .mount(&upstream)
        .await;

    let h = harness(&upstream.uri()).await;
    for (from, to) in [
        (
            "/api/keyed/v1/go",
            "http://locksmith.test:9200/api/keyed/v1/next?a=1",
        ),
        (
            "/api/keyed/v1/dir/go",
            "http://locksmith.test:9200/api/keyed/v1/dir/sibling",
        ),
    ] {
        let resp = h
            .server
            .get(from)
            .add_header("host", "locksmith.test:9200")
            .await;
        assert_eq!(resp.status_code(), 302, "{from}");
        assert_eq!(resp.headers()["location"], to, "{from}");
    }
}

/// A redirect envelope is not the final response: on a route with response
/// controls it is returned with its `Location` and an empty body, rather
/// than failing the content-type allowlist meant for the final response.
#[tokio::test]
async fn redirect_passes_response_controls_without_its_body() {
    let upstream = MockServer::start().await;
    Mock::given(path("/go"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", "/next")
                .set_body_raw(b"<a href=/next>moved</a>".to_vec(), "text/html"),
        )
        .mount(&upstream)
        .await;
    let controls = r#"    response:
      content_type_allowlist: ["application/json"]
      redaction_patterns:
        - id: never
          regex: "never-matches-xyz"
"#;

    let h = harness_with(&upstream.uri(), controls).await;
    let resp = h
        .server
        .get("/api/keyed/go")
        .add_header("host", "locksmith.test:9200")
        .await;

    assert_eq!(resp.status_code(), 302);
    assert_eq!(
        resp.headers()["location"],
        "http://locksmith.test:9200/api/keyed/next"
    );
    assert!(
        resp.as_bytes().is_empty(),
        "unapproved redirect body passed"
    );
    assert!(resp.headers().get("content-type").is_none());
}
