//! #155 — route backend follow-ups: the active-backend check sits in the
//! write transaction, the list shows the active backend from the route,
//! a malformed If-Match is 400, and restores keep exact bindings and
//! drop stale or dead ones.

#[path = "support/broker.rs"]
mod broker;

use agent_locksmith::config::EgressMode;
use agent_locksmith::registrations::AuthSpec;
use agent_locksmith::registrations::backends::{BackendError, BackendRepository, RouteBackend};
use axum::http::Method;
use broker::{H, setup, upstream_body};
use serde_json::{Value, json};

async fn revision(h: &H) -> i64 {
    h.op_req(Method::GET, "/routes/r/backends")
        .await
        .json::<Value>()["revision"]
        .as_i64()
        .unwrap()
}

async fn switch(h: &H, to: &str) -> Value {
    let rev = revision(h).await;
    let r = h
        .op_req(Method::POST, "/routes/r/switch")
        .add_header("if-match", &rev.to_string())
        .json(&json!({ "backend": to }))
        .await;
    r.assert_status_ok();
    r.json()
}

/// Route `r` on `a.example`, granted, plus a declared backend `b`.
async fn route(h: &H) {
    h.put_model("r", upstream_body("https://a.example"))
        .await
        .assert_status_ok();
    h.grant(&["r"]).await;
    h.op_req(Method::PUT, "/routes/r/backends/b")
        .json(
            &json!({ "upstream": "https://b.example", "egress": "direct",
                       "auth": { "kind": "none" } }),
        )
        .await
        .assert_status_ok();
}

async fn binding(h: &H) -> Option<String> {
    sqlx::query_scalar(
        "SELECT auth_spec FROM agent_credential_overrides o JOIN agents a ON a.id = o.agent_id \
         WHERE a.public_id = ? AND o.registration = 'r'",
    )
    .bind(&h.pid)
    .fetch_optional(&h.pool)
    .await
    .unwrap()
}

async fn seal_binding(h: &H, value: &str) {
    h.op_req(
        Method::PUT,
        &format!("/agents/{}/credentials/r/credential", h.pid),
    )
    .json(&json!({ "value": value }))
    .await
    .assert_status_ok();
}

fn backend(name: &str) -> RouteBackend {
    RouteBackend {
        route: "r".into(),
        name: name.into(),
        upstream: "https://c.example".into(),
        egress: EgressMode::Direct,
        upstream_ca_pem: None,
        auth: AuthSpec::None,
        broker: None,
        created_at: 0,
        updated_at: 0,
    }
}

#[tokio::test]
async fn repo_writes_refuse_the_active_backend() {
    let h = setup().await;
    route(&h).await;
    let repo = BackendRepository::new(h.pool.clone());
    assert!(matches!(
        repo.put(&backend("primary")).await,
        Err(BackendError::ActiveBackend)
    ));
    switch(&h, "b").await;
    assert!(matches!(
        repo.put(&backend("b")).await,
        Err(BackendError::ActiveBackend)
    ));
    assert!(matches!(
        repo.delete("r", "b").await,
        Err(BackendError::ActiveBackend)
    ));
    assert!(repo.delete("r", "primary").await.unwrap());
}

#[tokio::test]
async fn list_shows_the_active_backend_from_the_route() {
    let h = setup().await;
    route(&h).await;
    let list: Value = h.op_req(Method::GET, "/routes/r/backends").await.json();
    let names: Vec<_> = list["backends"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["b", "primary"]);
    let primary = |v: &Value| {
        v["backends"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["name"] == "primary")
            .unwrap()
            .clone()
    };
    assert_eq!(primary(&list)["upstream"], "https://a.example");

    h.put_model("r", upstream_body("https://a2.example"))
        .await
        .assert_status_ok();
    let list: Value = h.op_req(Method::GET, "/routes/r/backends").await.json();
    assert_eq!(primary(&list)["upstream"], "https://a2.example");
    let one: Value = h
        .op_req(Method::GET, "/routes/r/backends/primary")
        .await
        .json();
    assert_eq!(one["upstream"], "https://a2.example");
}

#[tokio::test]
async fn malformed_if_match_is_400() {
    let h = setup().await;
    route(&h).await;
    let r = h
        .op_req(Method::POST, "/routes/r/switch")
        .add_header("if-match", "not-a-revision")
        .json(&json!({ "backend": "b" }))
        .await;
    assert_eq!(r.status_code(), 400);
    assert_eq!(r.json::<Value>()["error"]["code"], "if_match_invalid");
}

#[tokio::test]
async fn restore_keeps_the_exact_binding() {
    let h = setup().await;
    route(&h).await;
    seal_binding(&h, "agent-key-1").await;
    let before = binding(&h).await.unwrap();
    switch(&h, "b").await;
    assert_eq!(binding(&h).await, None);
    let back = switch(&h, "primary").await;
    assert_eq!(back["bindings_restored"], 1);
    let after: Value = serde_json::from_str(&binding(&h).await.unwrap()).unwrap();
    assert_eq!(after, serde_json::from_str::<Value>(&before).unwrap());
}

#[tokio::test]
async fn recreated_backend_drops_its_stash() {
    let h = setup().await;
    route(&h).await;
    switch(&h, "b").await;
    h.bind("r", json!({ "kind": "none" }))
        .await
        .assert_status_ok();
    switch(&h, "primary").await;
    h.op_req(Method::DELETE, "/routes/r/backends/b")
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    h.op_req(Method::PUT, "/routes/r/backends/b")
        .json(
            &json!({ "upstream": "https://b.example", "egress": "direct",
                       "auth": { "kind": "none" } }),
        )
        .await
        .assert_status_ok();
    let to_b = switch(&h, "b").await;
    assert_eq!(
        to_b["bindings_restored"], 0,
        "a recreated backend starts empty"
    );
    assert_eq!(binding(&h).await, None);
}

#[tokio::test]
async fn dead_stored_binding_is_not_restored() {
    let h = setup().await;
    route(&h).await;
    seal_binding(&h, "agent-key-1").await;
    switch(&h, "b").await;
    sqlx::query("UPDATE credential_secrets SET tombstoned_at = unixepoch()")
        .execute(&h.pool)
        .await
        .unwrap();
    let back = switch(&h, "primary").await;
    assert_eq!(back["bindings_restored"], 0);
    assert_eq!(binding(&h).await, None);
}
