//! T1.9 — Cloud-provider streaming integration tests.
//!
//! **Local-only per Q-2 (PRD §14.1 #2).** These tests are explicitly NOT
//! part of the default CI lane. They run only when the relevant API key
//! env var is set; absent keys → tests skip with a clear `SKIP:` log
//! line.
//!
//! Engineers run these pre-PR, with credentials sourced from a local
//! shell or a 1Password / pass-managed dotenv. Cost per run is
//! negligible (≪ $0.001) because each test uses the cheapest model and
//! a minimal prompt that asks for ≤4 output tokens.
//!
//! Covers: UC-6, R-F12, R-N6.

use agent_locksmith::app::build_app;
use agent_locksmith::config::parse_config_str;
use futures_util::StreamExt;
use reqwest::Client;
use std::time::Duration;
use tokio::net::TcpListener;

async fn spawn_locksmith_for_cloud(
    name: &str,
    upstream: &str,
    auth_header: &str,
    auth_value: &str,
) -> String {
    // SAFETY: tests serialize via tokio runtime and we're setting unique
    // env-var names per cloud provider; no concurrent writes.
    unsafe {
        std::env::set_var(
            format!("LOCKSMITH_TEST_KEY_{name}").to_uppercase(),
            auth_value,
        );
    }
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 0
tools:
  - name: "{name}"
    description: "{name}"
    upstream: "{upstream}"
    egress: "direct"
    auth:
      header: "{auth_header}"
      value: "${{LOCKSMITH_TEST_KEY_{}}}"
    timeouts:
      request_seconds: 120
      idle_seconds: 120
"#,
        name.to_uppercase()
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
async fn anthropic_streams_completion_through_locksmith() {
    let Ok(key) = std::env::var("ANTHROPIC_API_KEY") else {
        eprintln!("SKIP: ANTHROPIC_API_KEY not set; export it locally to run this test");
        return;
    };

    let proxy =
        spawn_locksmith_for_cloud("anthropic", "https://api.anthropic.com", "x-api-key", &key)
            .await;

    let client = Client::new();
    let resp = client
        .post(format!("{proxy}/api/anthropic/v1/messages"))
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "model": "claude-haiku-4-5",
            "max_tokens": 4,
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .expect("anthropic via locksmith");

    assert!(
        resp.status().is_success(),
        "Anthropic returned {}; body={:?}",
        resp.status(),
        resp.text().await.ok()
    );

    let mut chunks = 0;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        chunk.expect("chunk ok");
        chunks += 1;
    }
    assert!(chunks > 0, "expected at least one streaming chunk");
}

#[tokio::test]
async fn openai_streams_completion_through_locksmith() {
    let Ok(key) = std::env::var("OPENAI_API_KEY") else {
        eprintln!("SKIP: OPENAI_API_KEY not set; export it locally to run this test");
        return;
    };

    let proxy = spawn_locksmith_for_cloud(
        "openai",
        "https://api.openai.com",
        "Authorization",
        &format!("Bearer {key}"),
    )
    .await;

    let client = Client::new();
    let resp = client
        .post(format!("{proxy}/api/openai/v1/chat/completions"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "model": "gpt-4o-mini",
            "max_tokens": 4,
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .expect("openai via locksmith");

    assert!(
        resp.status().is_success(),
        "OpenAI returned {}; body={:?}",
        resp.status(),
        resp.text().await.ok()
    );

    let mut chunks = 0;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        chunk.expect("chunk ok");
        chunks += 1;
    }
    assert!(chunks > 0, "expected at least one streaming chunk");
}
