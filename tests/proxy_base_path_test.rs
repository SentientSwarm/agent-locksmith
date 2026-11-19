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
        // Escapes the upstream resolves after decoding once more, or after
        // dropping `;` parameters (nginx, Tomcat).
        "..%252F..%252Fsecret",
        "%252e%252e%252Fsecret",
        "..;/secret",
        "..%3Bx/secret",
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
    assert_eq!(refused, 13);
}

/// AGENT-287 — an escaped path too long to judge is refused with its own
/// code, so the audit tells it from an escape.
#[tokio::test]
async fn a_path_too_long_to_check_has_its_own_code() {
    let up = upstream().await;
    let b = build(config(&format!("{}/base/api", up.uri()), "  routes: []\n")).await;
    // The router decodes once, so each repeat is six bytes at the check.
    let long = "a%252Fb/".repeat(16 * 1024 / 6 + 1);
    let (status, body) = get(&b, &format!("/api/out/{long}x")).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "path_too_long");
    let (status, body) = get(&b, "/api/out/%2e%2e/secret").await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "upstream_path_escape");
    assert!(up.received_requests().await.unwrap().is_empty());
    let count = |event: &'static str| {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit WHERE event = ?")
            .bind(event)
            .fetch_one(&b.pool)
    };
    assert_eq!(count("path_too_long").await.unwrap(), 1);
    assert_eq!(count("upstream_path_escape").await.unwrap(), 1);
}

#[tokio::test]
async fn paths_inside_the_base_path_still_forward() {
    let up = upstream().await;
    let b = build(config(&format!("{}/base/api", up.uri()), "  routes: []\n")).await;
    for path in [
        "x/y",
        "x/%2e%2e/y",
        "a.b/..c",
        "%2e%2efile",
        // GitLab-style encoded slashes stay inside the base.
        "projects/group%252Fproj",
        "x/..%252Fy",
        "v;a=1/y",
    ] {
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

/// AGENT-290 — the upstream's root (and the base path itself) is a valid
/// target: `/api/<route>/` and `/api/<route>` forward to `<upstream>/`,
/// query included, instead of falling through to the router's 404.
#[tokio::test]
async fn the_upstream_root_is_forwarded() {
    let up = upstream().await;
    let b = build(config(&format!("{}/base/api", up.uri()), "  routes: []\n")).await;
    for path in ["/api/out/?q=x&format=json", "/api/out?q=y", "/api/out/"] {
        let (status, _) = get(&b, path).await;
        assert_eq!(status, 200, "{path}");
    }
    let seen: Vec<(String, Option<String>)> = up
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| (r.url.path().to_string(), r.url.query().map(str::to_string)))
        .collect();
    assert_eq!(
        seen,
        vec![
            (
                "/base/api/".to_string(),
                Some("q=x&format=json".to_string())
            ),
            // Without the slash the upstream URL is used exactly.
            ("/base/api".to_string(), Some("q=y".to_string())),
            ("/base/api/".to_string(), None),
        ]
    );
}

/// AGENT-290 — a redirect from the root to the bare base comes back through
/// Locksmith, so the agent's next request does not go around it.
#[tokio::test]
async fn a_root_redirect_points_back_at_locksmith() {
    let up = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(301)
                .insert_header("location", format!("{}/base/api?page=2", up.uri()).as_str()),
        )
        .mount(&up)
        .await;
    let b = build(config(&format!("{}/base/api", up.uri()), "  routes: []\n")).await;
    let req = Request::builder()
        .uri("/api/out/")
        .header("authorization", &b.auth)
        .header("host", "ls.test:9200")
        .body(Body::empty())
        .unwrap();
    let resp = b.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 301);
    assert_eq!(
        resp.headers()["location"],
        "http://ls.test:9200/api/out?page=2"
    );
}
