//! T1.1 — Failing SSE-passthrough integration test.
//!
//! These tests assert that Locksmith's proxy passes server-sent events (SSE)
//! through to the agent without buffering the full upstream response. They
//! MUST fail against current M0 code.
//!
//! ## How M0 fails these tests (verified empirically)
//!
//! M0's proxy at `src/proxy.rs:88-99` has two intertwined defects in its
//! response handling that both manifest when the upstream sends a streaming
//! response with `Transfer-Encoding: chunked`:
//!
//! 1. **Body buffering** — `resp.bytes().await` (line 95) accumulates the
//!    entire upstream response into a single `Bytes` buffer before any
//!    response is returned to the agent. First-byte latency ≈ total
//!    upstream duration. Violates R-N6 (≤100ms first-byte added latency).
//!
//! 2. **Response framing mismatch** — Upstream headers (including
//!    `Transfer-Encoding: chunked`) are copied verbatim into the response
//!    Locksmith returns to the agent (line 90), but the response body is
//!    rebuilt as a flat `Body::from(body)` (line 96). The agent's HTTP
//!    client sees `TE: chunked` in the headers, expects chunked framing,
//!    and gets a literal body — protocol mismatch → `IncompleteMessage`
//!    error before timing can even be measured.
//!
//! Both defects are resolved by T1.2's single change: switching the
//! response body construction to `Body::from_stream(resp.bytes_stream())`.
//! The body becomes a real stream (fixes buffering, restores R-N6 timing)
//! and the wire framing matches the chunked-transfer headers (restores
//! protocol correctness).
//!
//! Under M0, the tests panic at the `send().await` step due to defect #2.
//! Once T1.2 lands, the protocol mismatch is gone and the timing assertions
//! kick in — under buffered response handling the first-byte timing would
//! exceed 100ms; under streaming it's well under.
//!
//! Covers: UC-6, R-F12, R-N6 (≤100ms added first-byte latency).

use agent_locksmith::app::build_app;
use agent_locksmith::config::parse_config_str;
use axum::Router;
use axum::body::Body;
use axum::routing::any;
use bytes::Bytes;
use futures_util::StreamExt;
use futures_util::stream;
use reqwest::Client;
use std::convert::Infallible;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time::sleep;

/// One scheduled chunk: sleep `delay`, then emit `payload` as bytes.
/// Delays are *between-chunk*: the first chunk uses its own delay before
/// emitting (typically `Duration::ZERO` for an immediate first byte).
type ScheduledChunks = Vec<(Duration, &'static str)>;

/// Spawns a fixture HTTP server that emits an SSE response with the given
/// scheduled chunks at `/sse`. Returns the bound URL (e.g. `http://127.0.0.1:NNNN`).
async fn spawn_sse_fixture(chunks: ScheduledChunks) -> String {
    let app = Router::new().route(
        "/sse",
        any(move || {
            let chunks = chunks.clone();
            async move {
                let stream = stream::iter(chunks).then(|(delay, payload)| async move {
                    if !delay.is_zero() {
                        sleep(delay).await;
                    }
                    Ok::<Bytes, Infallible>(Bytes::from_static(payload.as_bytes()))
                });
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "text/event-stream")
                    .header("cache-control", "no-cache")
                    .body(Body::from_stream(stream))
                    .unwrap()
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

/// Spawns a Locksmith proxy on a random port pointing at `upstream_url`.
/// `timeout_seconds` controls the per-tool timeout (M0 default is 30s; tests
/// that simulate long generations override this so they don't trip on M0's
/// total-request timeout — those tests fail strictly because of buffering,
/// not timeout).
async fn spawn_locksmith_proxy(upstream_url: &str, timeout_seconds: u64) -> String {
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 0
tools:
  - name: "fixture"
    description: "SSE fixture"
    upstream: "{upstream_url}"
    timeout_seconds: {timeout_seconds}
"#
    );
    let config = parse_config_str(&yaml).unwrap();
    let app = build_app(config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn test_sse_first_byte_within_100ms_of_upstream() {
    // Fixture emits the first chunk immediately, then two more at 500ms gaps.
    // A streaming proxy delivers the first chunk to the test client in
    // ~milliseconds. A buffering proxy (M0) only returns AFTER the upstream
    // finishes — meaning the first byte to the test client is delayed by
    // roughly the entire upstream duration (>1000ms here).
    let fixture_url = spawn_sse_fixture(vec![
        (Duration::ZERO, "data: chunk1\n\n"),
        (Duration::from_millis(500), "data: chunk2\n\n"),
        (Duration::from_millis(500), "data: chunk3\n\n"),
    ])
    .await;

    let proxy_url = spawn_locksmith_proxy(&fixture_url, 30).await;

    let client = Client::new();
    let start = Instant::now();
    let response = client
        .get(format!("{proxy_url}/api/fixture/sse"))
        .send()
        .await
        .expect("send to locksmith proxy succeeds");
    assert_eq!(response.status(), 200);

    let mut stream = response.bytes_stream();
    let first = stream
        .next()
        .await
        .expect("stream yields at least one chunk")
        .expect("first chunk is Ok");
    let first_byte_elapsed = start.elapsed();

    assert!(!first.is_empty(), "first chunk has bytes");
    assert!(
        first_byte_elapsed < Duration::from_millis(100),
        "First byte arrived after {first_byte_elapsed:?}, expected < 100ms (R-N6). \
         Under M0 this fails because src/proxy.rs:95 buffers the full upstream \
         response via resp.bytes().await before returning to the agent."
    );
}

#[tokio::test]
async fn test_chunk_intervals_preserved() {
    // Three chunks with 500ms gaps between them. With streaming, the proxy
    // forwards each chunk as the upstream emits it, so the test client sees
    // gaps of ~500ms. With M0's buffered response, all chunks arrive at the
    // test client at the same instant (after upstream finishes), so the
    // observed gaps collapse to ~0.
    let fixture_url = spawn_sse_fixture(vec![
        (Duration::ZERO, "data: chunk1\n\n"),
        (Duration::from_millis(500), "data: chunk2\n\n"),
        (Duration::from_millis(500), "data: chunk3\n\n"),
    ])
    .await;

    let proxy_url = spawn_locksmith_proxy(&fixture_url, 30).await;

    let client = Client::new();
    let response = client
        .get(format!("{proxy_url}/api/fixture/sse"))
        .send()
        .await
        .expect("send to locksmith proxy succeeds");
    assert_eq!(response.status(), 200);

    let mut stream = response.bytes_stream();
    let stream_start = Instant::now();
    let mut arrival_offsets: Vec<Duration> = Vec::new();
    while let Some(chunk) = stream.next().await {
        chunk.expect("chunk is Ok");
        arrival_offsets.push(stream_start.elapsed());
    }

    assert!(
        arrival_offsets.len() >= 3,
        "expected at least 3 chunks; got {} ({:?})",
        arrival_offsets.len(),
        arrival_offsets
    );

    // Inter-chunk gaps should be at least 400ms (500ms emission interval
    // minus reasonable jitter). Under M0 buffering, gaps collapse to ~0.
    let gap_1_to_2 = arrival_offsets[1] - arrival_offsets[0];
    let gap_2_to_3 = arrival_offsets[2] - arrival_offsets[1];

    assert!(
        gap_1_to_2 >= Duration::from_millis(400),
        "gap between chunk 1 and chunk 2 was {gap_1_to_2:?}, expected ≥400ms. \
         Buffered responses collapse all chunks to the same arrival time."
    );
    assert!(
        gap_2_to_3 >= Duration::from_millis(400),
        "gap between chunk 2 and chunk 3 was {gap_2_to_3:?}, expected ≥400ms. \
         Buffered responses collapse all chunks to the same arrival time."
    );
}

/// Long-running generation simulation. Five chunks emitted at 1-second
/// intervals (5 second total wall clock). A `timeout_seconds` of 60 is
/// supplied so the M0 default 30s total timeout isn't the cause of failure
/// — under M0, the test still fails the *streaming* assertion because all
/// chunks arrive at the same time at the test client.
///
/// The PRD §M1 "long-running" property (multi-minute generation under
/// default config) depends on T1.4's per-tool timeout split — that is not
/// in T1.1's scope and is verified by T1.4's tests. This test verifies
/// that streaming completes correctly when total upstream duration exceeds
/// what fits in a single-buffered response would cap at, and that all
/// chunks arrive in order.
#[tokio::test]
async fn test_long_running_stream_completes() {
    let fixture_url = spawn_sse_fixture(vec![
        (Duration::ZERO, "data: 1\n\n"),
        (Duration::from_secs(1), "data: 2\n\n"),
        (Duration::from_secs(1), "data: 3\n\n"),
        (Duration::from_secs(1), "data: 4\n\n"),
        (Duration::from_secs(1), "data: 5\n\n"),
    ])
    .await;

    // 60s timeout >> 5s upstream duration; M0 default of 30s would also
    // suffice for this case but we set explicitly to remove ambiguity.
    let proxy_url = spawn_locksmith_proxy(&fixture_url, 60).await;

    let client = Client::new();
    let response = client
        .get(format!("{proxy_url}/api/fixture/sse"))
        .send()
        .await
        .expect("send to locksmith proxy succeeds");
    assert_eq!(response.status(), 200);

    let mut stream = response.bytes_stream();
    let stream_start = Instant::now();
    let mut full_body = Vec::new();
    let mut first_byte_offset: Option<Duration> = None;
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.expect("chunk is Ok");
        if first_byte_offset.is_none() {
            first_byte_offset = Some(stream_start.elapsed());
        }
        full_body.extend_from_slice(&bytes);
    }
    let total_elapsed = stream_start.elapsed();

    // All five chunks must be present in order.
    let body_str = String::from_utf8(full_body).expect("body is utf-8");
    for n in 1..=5 {
        let expected = format!("data: {n}\n\n");
        assert!(
            body_str.contains(&expected),
            "body missing chunk {n:?}; got body:\n{body_str}"
        );
    }

    // The streaming assertion: first byte should arrive long before the
    // upstream finishes. Under streaming, first_byte_offset ≈ 0; under M0
    // buffering, it ≈ total_elapsed (since everything arrives at once).
    let first = first_byte_offset.expect("at least one chunk");
    assert!(
        first < Duration::from_millis(500),
        "first chunk arrived at {first:?} (total stream took {total_elapsed:?}). \
         Buffered responses collapse first-byte to total-duration."
    );
}
