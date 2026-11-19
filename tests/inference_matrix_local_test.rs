//! T1.8 — Local-upstream inference matrix integration tests.
//!
//! Verifies M1's streaming proxy against:
//! - A local fixture serving an OpenAI-compatible streaming chat-completion
//!   response (always present in CI; uses the M1 streaming infrastructure
//!   directly).
//! - Ollama, when reachable at `OLLAMA_HOST` (default `localhost:11434`).
//! - LM Studio, when reachable at `LMSTUDIO_HOST` (default `localhost:1234`).
//!
//! Tests against absent local services are skipped (logged via eprintln!)
//! rather than failing — developers without Ollama/LM Studio installed
//! still get a green test run.
//!
//! Cloud-provider tests (Anthropic, OpenAI) live in
//! `tests/inference_matrix_cloud_test.rs` and are local-only per Q-2.
//!
//! Covers: UC-6, UC-13, R-F12, R-F13, R-N6.

#[path = "support/registered_legacy.rs"]
mod registered_legacy;

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

/// OpenAI-shaped streaming chat-completion response. Each `data:` line is
/// one delta chunk; the stream ends with `data: [DONE]\n\n`.
async fn spawn_openai_compatible_fixture() -> String {
    let chunks = vec![
        (
            Duration::ZERO,
            "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n",
        ),
        (
            Duration::from_millis(150),
            "data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n",
        ),
        (
            Duration::from_millis(150),
            "data: {\"choices\":[{\"delta\":{\"content\":\"!\"}}]}\n\n",
        ),
        (Duration::from_millis(50), "data: [DONE]\n\n"),
    ];

    let app = Router::new().route(
        "/v1/chat/completions",
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

async fn spawn_locksmith_for(upstream: &str) -> (String, Client) {
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 0
tools:
  - name: "openai-shaped"
    description: "OpenAI-compatible upstream"
    upstream: "{upstream}"
    egress: "direct"
    timeouts:
      request_seconds: 60
      idle_seconds: 60
"#
    );
    let (url, bearer) = registered_legacy::spawn(parse_config_str(&yaml).unwrap()).await;
    (url, agent_client(&bearer))
}

/// A client that authenticates as the fixture's enrolled agent.
fn agent_client(bearer: &str) -> Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, bearer.parse().unwrap());
    Client::builder().default_headers(headers).build().unwrap()
}

#[tokio::test]
async fn fixture_streams_chat_completion_through_locksmith() {
    let upstream = spawn_openai_compatible_fixture().await;
    let (proxy, client) = spawn_locksmith_for(&upstream).await;

    let start = Instant::now();
    let resp = client
        .post(format!("{proxy}/api/openai-shaped/v1/chat/completions"))
        .json(&serde_json::json!({
            "model": "stub",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
        }))
        .send()
        .await
        .expect("send to locksmith proxy");
    assert_eq!(resp.status(), 200);

    let mut full = Vec::new();
    let mut first_byte: Option<Duration> = None;
    let mut last_byte = Duration::ZERO;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.expect("chunk ok");
        if first_byte.is_none() {
            first_byte = Some(start.elapsed());
        }
        last_byte = start.elapsed();
        full.extend_from_slice(&bytes);
    }
    let body = String::from_utf8(full).expect("utf-8 body");
    assert!(body.contains("hello"));
    assert!(body.contains("world"));
    assert!(body.contains("[DONE]"));

    // R-N6: Locksmith streams rather than buffers. The fixture spreads its
    // chunks over 350 ms, so the first byte must reach the client at least
    // one 150 ms gap before the last; a buffering proxy delivers them
    // together. A wall-clock bound on the first byte measured the host, not
    // Locksmith, and failed under load (AGENT-327); the latency target
    // itself is streaming_passthrough_test's, relative to auth. The 5 s
    // bound only catches a stall.
    let first = first_byte.expect("at least one chunk");
    assert!(
        last_byte.saturating_sub(first) >= Duration::from_millis(150),
        "first byte {first:?}, last byte {last_byte:?}: the stream was buffered"
    );
    assert!(
        first < Duration::from_secs(5),
        "first byte stalled: {first:?}"
    );
}

/// Probe a TCP host:port. Returns true if a TCP connection can be
/// established within `timeout`. Used to decide whether Ollama / LM
/// Studio integration tests should run.
async fn host_reachable(addr: &str, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some()
}

#[tokio::test]
async fn ollama_streams_chat_through_locksmith_when_present() {
    let host = std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "localhost:11434".to_string());
    let host_for_url = host.clone();
    if !host_reachable(&host, Duration::from_millis(200)).await {
        eprintln!("SKIP: ollama not reachable at {host}; set OLLAMA_HOST to enable");
        return;
    }

    let upstream = format!("http://{host_for_url}");
    let (proxy, client) = spawn_locksmith_for(&upstream).await;

    // /api/tags is the cheapest readiness probe Ollama offers — no model
    // download required. We're verifying the proxy reaches Ollama and
    // forwards the response, not generation latency. Any non-5xx is a
    // pass: 2xx = ok, 4xx = upstream rejected the request shape (still
    // proves the proxy reached Ollama and forwarded the response).
    let resp = client
        .get(format!("{proxy}/api/openai-shaped/api/tags"))
        .send()
        .await
        .expect("ollama via locksmith");
    assert!(
        !resp.status().is_server_error(),
        "expected non-5xx (any 2xx/4xx proves proxy reached upstream); got {}",
        resp.status()
    );
}

#[tokio::test]
async fn lmstudio_streams_chat_through_locksmith_when_present() {
    let host = std::env::var("LMSTUDIO_HOST").unwrap_or_else(|_| "localhost:1234".to_string());
    let host_for_url = host.clone();
    if !host_reachable(&host, Duration::from_millis(200)).await {
        eprintln!("SKIP: LM Studio not reachable at {host}; set LMSTUDIO_HOST to enable");
        return;
    }

    let upstream = format!("http://{host_for_url}");
    let (proxy, client) = spawn_locksmith_for(&upstream).await;

    // /v1/models is LM Studio's catalog endpoint — no generation cost.
    // Any non-5xx is a pass: 2xx = ok, 4xx = upstream rejected (e.g.
    // 401 when LM Studio's API-token auth is enabled — the test doesn't
    // inject auth, that's the seed catalog's job in production). What
    // we're proving here is that locksmith reached the upstream and
    // forwarded a valid HTTP response.
    let resp = client
        .get(format!("{proxy}/api/openai-shaped/v1/models"))
        .send()
        .await
        .expect("lmstudio via locksmith");
    assert!(
        !resp.status().is_server_error(),
        "expected non-5xx (any 2xx/4xx proves proxy reached upstream); got {}",
        resp.status()
    );
}
