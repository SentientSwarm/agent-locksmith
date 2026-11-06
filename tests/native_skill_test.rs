//! Exercise the real optional-auth route and shared discovery, without native calls.
#[path = "native/fixture.rs"]
mod fixture;
use axum::body::to_bytes;
use fixture::Fixture;
use serde_json::Value;

async fn personal(f: &Fixture) -> String {
    let response = f.request("/skill", "GET", Value::Null, None).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["cache-control"],
        "private, no-cache, no-store"
    );
    assert_eq!(
        response.headers()["content-type"],
        "text/markdown; charset=utf-8"
    );
    String::from_utf8(
        to_bytes(response.into_body(), 262144)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn agrees(f: &Fixture, expected: &[(&str, &str)]) -> String {
    let listing = fixture::rpc(f.request("/tools", "GET", Value::Null, None).await).await;
    let tools = listing["tools"].as_array().unwrap();
    assert_eq!(tools.len(), expected.len());
    for (name, kind) in expected {
        assert!(
            tools
                .iter()
                .any(|v| v["name"] == *name && v["type"] == *kind)
        );
    }
    let text = personal(f).await;
    let part = text.split("## Personalized for").nth(1).unwrap();
    for tool in tools {
        let path = tool["path"].as_str().unwrap();
        assert!(
            part.contains(path),
            "personalized guidance lost discovery path {path}"
        );
    }
    text
}

#[tokio::test]
async fn native_only_skill_preserves_discovery_route() {
    let f = Fixture::new("").await;
    let text = agrees(&f, &[("native", "mcp"), ("other", "mcp")]).await;
    let part = text.split("## Personalized for").nth(1).unwrap();
    assert!(part.contains("Native MCP connections"));
    assert!(!part.contains("http://<locksmith>/api/<tool>"));
    assert!(text.contains("tools/list") && text.contains("tools/call"));
    assert_eq!(f.runtime.snapshot().entries, 0);
}

#[tokio::test]
async fn mixed_skill_preserves_both_protocol_routes() {
    let f = Fixture::new("").await;
    let mut http = f.repo.get("other").await.unwrap().unwrap();
    http.protocol = agent_locksmith::registrations::Protocol::Http;
    http.mcp = None;
    f.repo.upsert(&http).await.unwrap();
    // A protocol update deliberately clears old connection authority.
    sqlx::query("UPDATE agents SET tool_allowlist='[\"native\",\"other\"]' WHERE id=?")
        .bind(f.agent_id)
        .execute(&f.pool)
        .await
        .unwrap();
    f.refresh().await;
    let text = agrees(&f, &[("native", "mcp"), ("other", "api")]).await;
    assert!(text.contains("HTTP connections") && text.contains("Native MCP connections"));
    assert_eq!(f.runtime.snapshot().entries, 0);
}

#[tokio::test]
async fn discovery_changes_and_empty_inventory_do_not_promise_native_calls() {
    let f = Fixture::new("").await;
    let session = f.open().await;
    let tools = fixture::rpc(f.call(&session, 1, "tools/list").await).await;
    assert_eq!(tools["result"]["tools"], serde_json::json!([]));
    let text = agrees(&f, &[("native", "mcp"), ("other", "mcp")]).await;
    assert!(text.contains("not native callable-tool inventory"));
    f.request("/mcp/native", "DELETE", Value::Null, Some(&session))
        .await;
    fixture::released(&f).await;
    f.repo.set_disabled("other", true).await.unwrap();
    let text = agrees(&f, &[("native", "mcp")]).await;
    assert!(!text.contains("/mcp/other"));
    // A persisted change before runtime activation disappears in both surfaces.
    let mut native = f.repo.get("native").await.unwrap().unwrap();
    native.description = "pending-description".into();
    f.repo.upsert(&native).await.unwrap();
    let text = agrees(&f, &[]).await;
    assert!(text.contains("No tools currently available"));
    f.refresh().await;
    agrees(&f, &[("native", "mcp")]).await;
    sqlx::query("UPDATE agents SET tool_denylist='[\"native\"]' WHERE id=?")
        .bind(f.agent_id)
        .execute(&f.pool)
        .await
        .unwrap();
    agrees(&f, &[]).await;
}
