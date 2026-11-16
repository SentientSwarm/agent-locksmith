//! AGENT-281 — a `databento-historical` route forwards only Databento
//! metadata requests; everything else is refused before anything leaves.

#[path = "support/broker.rs"]
mod broker;

use broker::{H, setup, upstream_body};
use serde_json::{Value, json};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn databento_route(h: &H, upstream_suffix: &str) -> MockServer {
    let up = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
        .mount(&up)
        .await;
    let mut body = upstream_body(&format!("{}{upstream_suffix}", up.uri()));
    body["policy"] = json!("databento-historical");
    h.put_model("db", body).await.assert_status_ok();
    h.grant(&["db"]).await;
    h.bind("db", json!({ "kind": "none" }))
        .await
        .assert_status_ok();
    up
}

async fn post(h: &H, path: &str) -> axum_test::TestResponse {
    h.agent
        .post(&format!("/api/db{path}"))
        .add_header("authorization", &h.agent_bearer)
        .content_type("application/x-www-form-urlencoded")
        .bytes("dataset=GLBX.MDP3".into())
        .await
}

#[tokio::test]
async fn metadata_requests_are_forwarded() {
    let h = setup().await;
    let up = databento_route(&h, "").await;
    post(&h, "/v0/metadata.list_datasets")
        .await
        .assert_status_ok();
    h.call("db", "/v0/metadata.list_schemas?dataset=GLBX.MDP3")
        .await
        .assert_status_ok();
    let reqs = up.received_requests().await.unwrap();
    let paths: Vec<_> = reqs.iter().map(|r| r.url.path().to_string()).collect();
    assert_eq!(
        paths,
        ["/v0/metadata.list_datasets", "/v0/metadata.list_schemas"]
    );
}

#[tokio::test]
async fn versioned_upstream_takes_unversioned_paths() {
    let h = setup().await;
    let up = databento_route(&h, "/v0").await;
    post(&h, "/metadata.get_cost").await.assert_status_ok();
    let refused = post(&h, "/v0/metadata.get_cost").await;
    refused.assert_status_forbidden();
    let reqs = up.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].url.path(), "/v0/metadata.get_cost");
}

#[tokio::test]
async fn data_and_batch_requests_are_refused_and_never_sent() {
    let h = setup().await;
    let up = databento_route(&h, "").await;
    for path in [
        "/v0/timeseries.get_range",
        "/v0/batch.submit_job",
        "/v0/metadata.list_datasets%2F..%2Ftimeseries.get_range",
        "/v0//metadata.list_datasets",
    ] {
        let r = post(&h, path).await;
        r.assert_status_forbidden();
        assert_eq!(
            r.json::<Value>()["error"]["code"],
            "route_request_refused",
            "{path}"
        );
    }
    assert!(up.received_requests().await.unwrap().is_empty());
    let d = h.last_audit("route_request_refused").await;
    assert_eq!(d["route_policy"], "databento-historical");
    assert_eq!(d["refused"], "path");
}

#[tokio::test]
async fn other_methods_are_refused() {
    let h = setup().await;
    let up = databento_route(&h, "").await;
    let r = h
        .agent
        .delete("/api/db/v0/metadata.list_datasets")
        .add_header("authorization", &h.agent_bearer)
        .await;
    r.assert_status_forbidden();
    assert!(up.received_requests().await.unwrap().is_empty());
    assert_eq!(
        h.last_audit("route_request_refused").await["refused"],
        "method"
    );
}

#[tokio::test]
async fn policy_is_shown_validated_and_removable() {
    let h = setup().await;
    let up = databento_route(&h, "").await;
    let shown = h
        .op_req(axum::http::Method::GET, "/models/db")
        .await
        .json::<Value>();
    assert_eq!(shown["policy"], "databento-historical");

    let mut bad = upstream_body(&up.uri());
    bad["policy"] = json!("github-api");
    let r = h.put_model("db", bad).await;
    r.assert_status_bad_request();
    assert_eq!(r.json::<Value>()["error"]["code"], "invalid_policy");

    // A put without the field removes the policy (PUT is a full replace).
    h.put_model("db", upstream_body(&up.uri()))
        .await
        .assert_status_ok();
    h.grant(&["db"]).await;
    h.bind("db", json!({ "kind": "none" }))
        .await
        .assert_status_ok();
    post(&h, "/v0/timeseries.get_range")
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn unrecognized_stored_policy_fails_closed() {
    let h = setup().await;
    let up = databento_route(&h, "").await;
    // A value only a newer build could have written.
    sqlx::query("UPDATE registrations SET policy = 'from-a-newer-build' WHERE name = 'db'")
        .execute(&h.pool)
        .await
        .unwrap();
    // Any operator write reloads the catalog, so runtime and stored rows agree.
    h.put_model("other", upstream_body("https://other.example"))
        .await
        .assert_status_ok();
    let r = post(&h, "/v0/metadata.list_datasets").await;
    r.assert_status_forbidden();
    assert_eq!(r.json::<Value>()["error"]["code"], "route_request_refused");
    assert!(up.received_requests().await.unwrap().is_empty());
    let d = h.last_audit("route_request_refused").await;
    assert_eq!(d["route_policy"], "unrecognized");
    assert_eq!(d["refused"], "policy");
}

#[tokio::test]
async fn sealed_basic_header_reaches_databento() {
    let h = setup().await;
    let up = databento_route(&h, "").await;
    // Databento auth: Basic base64("<key>:"), sealed per agent.
    h.op_req(
        axum::http::Method::PUT,
        &format!("/agents/{}/credentials/db/credential", h.pid),
    )
    .json(&json!({ "value": "Basic a2V5LTE6", "header": "Authorization" }))
    .await
    .assert_status_ok();
    post(&h, "/v0/metadata.list_datasets")
        .await
        .assert_status_ok();
    let reqs = up.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0]
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Basic a2V5LTE6"
    );
}
