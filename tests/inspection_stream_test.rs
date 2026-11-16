//! AGENT-265 — server-sent event responses inspected as they stream.
//!
//! Text fields of each event feed one sliding window. Under `flag` events
//! pass the moment they are complete; under `redact` or `block` they are
//! held until no match can reach back into them, so a key sent one
//! character per delta is caught before any of it reaches the agent.

use super::inspection_pipeline_test::{build, config, harness};
use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use futures_util::StreamExt;
use std::convert::Infallible;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn key() -> String {
    // Assembled at run time: no credential-format literal in the repo.
    format!(
        "ghp_{}",
        &"Tq3Wn8Ke5Rb2Yx7Lm4Hz9Dc6Fv1Gs0Pa".repeat(2)[..36]
    )
}

fn chat(delta: &str) -> String {
    let data = serde_json::json!({ "choices": [{ "index": 0, "delta": { "content": delta } }] });
    format!("data: {data}\n\n")
}

fn events() -> Vec<String> {
    let mut out = vec![chat("Here is the key: ")];
    out.extend(key().chars().map(|c| chat(&c.to_string())));
    out.push(chat(" and that is all."));
    out.push("data: [DONE]\n\n".into());
    out
}

/// An SSE upstream at any path. With a gate, it sends the first event,
/// then waits for the gate before the rest.
async fn upstream(events: Vec<String>, gate: Option<oneshot::Receiver<()>>) -> String {
    let gate = std::sync::Arc::new(tokio::sync::Mutex::new(gate));
    let app = axum::Router::new().fallback(move || {
        let events = events.clone();
        let gate = gate.clone();
        async move {
            let stream =
                futures_util::stream::iter(events.into_iter().enumerate()).then(move |(i, e)| {
                    let gate = gate.clone();
                    async move {
                        if i == 1
                            && let Some(g) = gate.lock().await.take()
                        {
                            let _ = g.await;
                        }
                        Ok::<Bytes, Infallible>(Bytes::from(e))
                    }
                });
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(Body::from_stream(stream))
                .unwrap()
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn policy(on_hit: &str) -> String {
    format!(
        "  routes:\n    - route: out\n      response:\n        scanners: [dlp]\n        on_hit: {on_hit}\n"
    )
}

#[tokio::test]
async fn split_key_is_redacted_before_the_agent_sees_it() {
    let url = upstream(events(), None).await;
    let h = harness(config(&url, &policy("redact"))).await;
    let resp = h
        .server
        .post("/api/out/x")
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(resp.status_code(), 200);
    let text = resp.text();
    let k = key();
    for start in 0..=k.len() - 8 {
        assert!(
            !text.contains(&k[start..start + 8]),
            "leaked part of the key"
        );
    }
    assert!(text.contains("[REDACTED:dlp]"));
    assert!(text.ends_with("data: [DONE]\n\n"));
    // The row is written when the stream ends, off the request path.
    let mut rows = Vec::new();
    for _ in 0..50 {
        rows = h.inspection_rows().await;
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(rows[0].2["hits"][0]["rule"], "github_token");
    assert_eq!(rows[0].2["count"], 1);
}

#[tokio::test]
async fn block_ends_the_stream_with_an_error_event() {
    let url = upstream(events(), None).await;
    let h = harness(config(&url, &policy("block"))).await;
    let text = h
        .server
        .post("/api/out/x")
        .json(&serde_json::json!({}))
        .await
        .text();
    assert!(text.contains("event: error"), "{text}");
    assert!(text.contains("inspection_blocked"));
    assert!(!text.contains(&key()[..8]));
    assert!(
        !text.contains("[DONE]"),
        "the stream went on after the block"
    );
}

#[tokio::test]
async fn flag_forwards_the_first_event_before_the_second_is_sent() {
    let (open, gate) = oneshot::channel();
    let url = upstream(events(), Some(gate)).await;
    let built = build(config(&url, &policy("flag"))).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, built.app).await;
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/out/x"))
        .header("authorization", &built.auth)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let mut body = resp.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), body.next())
        .await
        .expect("first event held back")
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("Here is the key"));
    open.send(()).unwrap();
    let mut rest = Vec::new();
    while let Some(chunk) = body.next().await {
        rest.extend_from_slice(&chunk.unwrap());
    }
    assert!(String::from_utf8_lossy(&rest).contains("[DONE]"));
}

#[tokio::test]
async fn route_redaction_patterns_still_apply_to_an_inspected_stream() {
    let mut events = vec![chat("ticket CASE-778899 opened")];
    events.push("data: [DONE]\n\n".into());
    let url = upstream(events, None).await;
    let cfg = agent_locksmith::config::parse_config_str(&format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "out"
    description: "Inspected route with response controls"
    upstream: "{url}"
    response:
      redaction_patterns:
        - id: case_id
          regex: "CASE-[0-9]{{6}}"
inspection:
{}
"#,
        policy("flag")
    ))
    .unwrap();
    let h = harness(cfg).await;
    let resp = h
        .server
        .post("/api/out/x")
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(resp.status_code(), 200);
    assert!(!resp.text().contains("CASE-778899"), "{}", resp.text());
}
