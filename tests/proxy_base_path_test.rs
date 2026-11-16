//! AGENT-286 — a route's upstream base path confines the agent.
//!
//! axum decodes `%2e%2e` to `..` before the upstream URL is built and the
//! URL parser resolves dot segments, so without a check a request climbs
//! out of the base path and carries the route's credential with it.

use crate::inspection_pipeline_test::{Built, build, config};
use axum::body::Body;
use axum::http::Request;
use serde_json::Value;
use tower::ServiceExt;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Sent through the router as raw bytes: HTTP test clients resolve
/// `%2e%2e` themselves, but an agent's client need not.
async fn get(b: &Built, path: &str) -> (u16, Value) {
    let req = Request::builder()
        .uri(path)
        .header("authorization", &b.auth)
        .body(Body::empty())
        .unwrap();
    let resp = b.app.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn upstream() -> MockServer {
    let up = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&up)
        .await;
    up
}

#[tokio::test]
async fn dot_segments_cannot_leave_the_base_path() {
    let up = upstream().await;
    let b = build(config(&format!("{}/base/api", up.uri()), "  routes: []\n")).await;
    for path in [
        "%2e%2e/secret",
        "%2E%2E/%2e%2e/secret",
        ".%2e/secret",
        "%2e./secret",
        "x/%2e%2e/%2e%2e/secret",
        "..%5Csecret",
        "%2e%2e%5C..%5Csecret",
        "%2e%2e",
        // Same prefix, different segment: /base/api -> /base/apix.
        "%2e%2e/apix",
    ] {
        let (status, body) = get(&b, &format!("/api/out/{path}")).await;
        assert_eq!(status, 400, "{path}");
        assert_eq!(body["error"]["code"], "upstream_path_escape", "{path}");
    }
    assert!(up.received_requests().await.unwrap().is_empty());
    let refused: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event = 'upstream_path_escape'")
            .fetch_one(&b.pool)
            .await
            .unwrap();
    assert_eq!(refused, 9);
}

#[tokio::test]
async fn paths_inside_the_base_path_still_forward() {
    let up = upstream().await;
    let b = build(config(&format!("{}/base/api", up.uri()), "  routes: []\n")).await;
    for path in ["x/y", "x/%2e%2e/y", "a.b/..c", "%2e%2efile"] {
        let (status, _) = get(&b, &format!("/api/out/{path}")).await;
        assert_eq!(status, 200, "{path}");
    }
    let paths: Vec<String> = up
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(
        paths.iter().all(|p| p.starts_with("/base/api/")),
        "{paths:?}"
    );
}
