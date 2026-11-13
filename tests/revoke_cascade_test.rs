//! #157 — revoking an agent removes its account bindings, stashed backend
//! bindings and grants in the same write, and `prune-revoked` clears what
//! an earlier revoke left behind. Audit carries counts, never values.

#[path = "support/broker.rs"]
mod broker;

use axum::http::Method;
use broker::{H, setup, upstream_body};
use serde_json::{Value, json};

/// Route `r` with the harness agent granted and bound, a second backend
/// `b` switched in (stashing the primary binding) and bound there too.
async fn authority(h: &H) {
    h.put_model("r", upstream_body("https://a.example"))
        .await
        .assert_status_ok();
    h.grant(&["r"]).await;
    h.bind("r", json!({ "kind": "none" }))
        .await
        .assert_status_ok();
    h.op_req(Method::PUT, "/routes/r/backends/b")
        .json(
            &json!({ "upstream": "https://b.example", "egress": "direct",
                       "auth": { "kind": "none" } }),
        )
        .await
        .assert_status_ok();
    let rev = h
        .op_req(Method::GET, "/routes/r/backends")
        .await
        .json::<Value>()["revision"]
        .as_i64()
        .unwrap();
    h.op_req(Method::POST, "/routes/r/switch")
        .add_header("if-match", &rev.to_string())
        .json(&json!({ "backend": "b" }))
        .await
        .assert_status_ok();
    h.bind("r", json!({ "kind": "none" }))
        .await
        .assert_status_ok();
}

async fn leftovers(h: &H) -> (i64, i64, String) {
    let id: i64 = sqlx::query_scalar("SELECT id FROM agents WHERE public_id = ?")
        .bind(&h.pid)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let count = |sql: &'static str| {
        let pool = h.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    let bindings =
        count("SELECT COUNT(*) FROM agent_credential_overrides WHERE agent_id = ?").await;
    let stashed = count("SELECT COUNT(*) FROM backend_bindings WHERE agent_id = ?").await;
    let allow: Option<String> =
        sqlx::query_scalar("SELECT tool_allowlist FROM agents WHERE id = ?")
            .bind(id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    (bindings, stashed, allow.unwrap_or_default())
}

#[tokio::test]
async fn revoke_removes_bindings_stashes_and_grants() {
    let h = setup().await;
    authority(&h).await;
    assert_eq!(leftovers(&h).await.0, 1);
    assert_eq!(leftovers(&h).await.1, 1);

    h.op_req(Method::POST, &format!("/agents/{}/revoke", h.pid))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    assert_eq!(leftovers(&h).await, (0, 0, "[]".into()));
    let d = h.last_audit("agent_revoke").await;
    assert_eq!(
        d["removed"],
        json!({ "bindings": 1, "stashed_bindings": 1, "grants": 1, "native_grant_sets": 0 })
    );
    assert!(!d.to_string().contains("\"r\""), "counts only: {d}");
}

#[tokio::test]
async fn prune_revoked_clears_an_earlier_revoke() {
    let h = setup().await;
    authority(&h).await;
    // A revoke from before this fix only set revoked_at.
    sqlx::query("UPDATE agents SET revoked_at = unixepoch() WHERE public_id = ?")
        .bind(&h.pid)
        .execute(&h.pool)
        .await
        .unwrap();

    let dry: Value = h
        .op_req(Method::POST, "/agents/prune-revoked")
        .json(&json!({ "dry_run": true }))
        .await
        .json();
    assert_eq!(dry["dry_run"], true);
    let agent = &dry["agents"][0];
    assert_eq!(agent["public_id"], h.pid.as_str());
    assert_eq!(agent["bindings"], json!(["r"]));
    assert_eq!(agent["stashed_bindings"], json!(["r/primary"]));
    assert_eq!(agent["grants"], 1);
    assert_eq!(leftovers(&h).await.0, 1, "a dry run changes nothing");

    let done: Value = h
        .op_req(Method::POST, "/agents/prune-revoked")
        .json(&json!({}))
        .await
        .json();
    assert_eq!(done["dry_run"], false);
    assert_eq!(done["agents"].as_array().unwrap().len(), 1);
    assert_eq!(leftovers(&h).await, (0, 0, "[]".into()));
    let d = h.last_audit("agent_prune_revoked").await;
    assert_eq!(
        d,
        json!({ "dry_run": false, "agents": 1, "bindings": 1,
                "stashed_bindings": 1, "grants": 1, "native_grant_sets": 0 })
    );

    let again: Value = h
        .op_req(Method::POST, "/agents/prune-revoked")
        .json(&json!({}))
        .await
        .json();
    assert_eq!(again["agents"], json!([]), "idempotent");
}

#[tokio::test]
async fn prune_revoked_leaves_live_agents_alone() {
    let h = setup().await;
    authority(&h).await;
    let r: Value = h
        .op_req(Method::POST, "/agents/prune-revoked")
        .json(&json!({}))
        .await
        .json();
    assert_eq!(r["agents"], json!([]));
    assert_eq!(leftovers(&h).await.0, 1);
    assert_eq!(leftovers(&h).await.1, 1);
}
