//! Brokered routes phase 3 — a route can be a broker: its spec round-trips,
//! is validated, cannot flip kind in place, and takes only `broker`
//! selections.

#[path = "support/broker.rs"]
mod broker;

use broker::{broker_body, setup, upstream_body};
use serde_json::{Value, json};

fn code(r: &axum_test::TestResponse) -> String {
    r.json::<Value>()["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn put_broker_route_round_trips() {
    let h = setup().await;
    h.put_model("pool", broker_body("https://broker.example", json!({})))
        .await
        .assert_status_ok();
    let got: Value = h
        .put_model(
            "pool",
            broker_body(
                "https://broker.example",
                json!({
                    "attribution": { "header": "x-account-label", "sensitive": true },
                    "health": { "path": "/healthz" }
                }),
            ),
        )
        .await
        .json();
    assert_eq!(got["broker"]["identity_header"], "X-Locksmith-Agent");
    assert_eq!(got["broker"]["attribution"]["header"], "x-account-label");
    assert_eq!(got["broker"]["attribution"]["sensitive"], true);
    assert_eq!(got["broker"]["health"]["path"], "/healthz");
    assert_eq!(got["broker"]["health"]["expect_status"], 200);
    assert_eq!(got["broker"]["health"]["interval_seconds"], 30);
    let disabled: Value = h
        .put_model(
            "pool",
            broker_body("https://broker.example", json!({ "identity_header": null })),
        )
        .await
        .json();
    assert!(disabled["broker"]["identity_header"].is_null());
    let plain: Value = h
        .put_model("plain", upstream_body("https://a.example"))
        .await
        .json();
    assert!(plain["broker"].is_null());
}

#[tokio::test]
async fn broker_validation_refuses() {
    let h = setup().await;
    let bad = [
        json!({ "identity_header": "bad header" }),
        json!({ "identity_header": "Authorization" }),
        json!({ "identity_header": "host" }),
        json!({ "attribution": { "header": "" } }),
        json!({ "health": { "path": "healthz" } }),
        json!({ "health": { "path": "/h?x=1" } }),
        json!({ "health": { "path": format!("/{}", "a".repeat(256)) } }),
        json!({ "health": { "path": "/h", "expect_status": 99 } }),
        json!({ "health": { "path": "/h", "expect_status": 600 } }),
        json!({ "health": { "path": "/h", "interval_seconds": 4 } }),
        json!({ "health": { "path": "/h", "interval_seconds": 3601 } }),
    ];
    for b in bad {
        let r = h
            .put_model("pool", broker_body("https://broker.example", b.clone()))
            .await;
        assert_eq!(r.status_code(), 400, "{b}");
        assert_eq!(code(&r), "invalid_broker", "{b}");
    }
    for auth in [
        json!({ "kind": "bearer", "env_var": "KEY" }),
        json!({ "kind": "header", "header": "X-Key", "env_var": "KEY" }),
    ] {
        let mut body = broker_body("https://broker.example", json!({}));
        body["auth"] = auth.clone();
        let r = h.put_model("pool", body).await;
        assert_eq!(r.status_code(), 400, "{auth}");
        assert_eq!(code(&r), "invalid_broker", "{auth}");
    }
    let mut keyed = broker_body(
        "https://broker.example",
        json!({ "identity_header": "x-pool-key" }),
    );
    keyed["auth"] =
        json!({ "kind": "stored_header", "header": "X-Pool-Key", "secret_ref": "cs_x" });
    let r = h.put_model("pool", keyed).await;
    assert_eq!(
        code(&r),
        "invalid_broker",
        "identity header equals the key header"
    );
}

#[tokio::test]
async fn broker_kind_change_refused() {
    let h = setup().await;
    h.put_model("up", upstream_body("https://a.example"))
        .await
        .assert_status_ok();
    let mut to_broker = broker_body("https://a.example", json!({}));
    to_broker["auth"] = json!({ "kind": "stored_bearer", "secret_ref": "cs_pending" });
    let r = h.put_model("up", to_broker).await;
    assert_eq!(r.status_code(), 409);
    assert_eq!(code(&r), "broker_kind_change");
    h.put_model("pool", broker_body("https://b.example", json!({})))
        .await
        .assert_status_ok();
    let mut to_upstream = upstream_body("https://b.example");
    to_upstream["auth"] = json!({ "kind": "stored_bearer", "secret_ref": "cs_pending" });
    let r = h.put_model("pool", to_upstream).await;
    assert_eq!(r.status_code(), 409);
    assert_eq!(code(&r), "broker_kind_change");
    let got: Value = h.op_req(axum::http::Method::GET, "/models/up").await.json();
    assert!(got["broker"].is_null(), "unchanged");
}

#[tokio::test]
async fn broker_selection_kind_enforced() {
    let h = setup().await;
    h.put_model("pool", broker_body("https://b.example", json!({})))
        .await
        .assert_status_ok();
    h.put_model("up", upstream_body("https://a.example"))
        .await
        .assert_status_ok();
    h.grant(&["pool", "up"]).await;
    for spec in [
        json!({ "kind": "stored_bearer", "secret_ref": "cs_x" }),
        json!({ "kind": "none" }),
    ] {
        let r = h.bind("pool", spec.clone()).await;
        assert_eq!(r.status_code(), 400, "{spec}");
        assert_eq!(code(&r), "grant_target_invalid", "{spec}");
    }
    h.bind("pool", json!({ "kind": "broker" }))
        .await
        .assert_status_ok();
    let r = h.bind("up", json!({ "kind": "broker" })).await;
    assert_eq!(r.status_code(), 400);
    assert_eq!(code(&r), "grant_target_invalid");
}

#[tokio::test]
async fn broker_spec_refused_as_template() {
    let h = setup().await;
    let mut body = broker_body("https://b.example", json!({}));
    body["auth"] = json!({ "kind": "broker" });
    let r = h.put_model("pool", body).await;
    assert_eq!(r.status_code(), 400);
    assert_eq!(code(&r), "invalid_broker");
    let mut plain = upstream_body("https://a.example");
    plain["auth"] = json!({ "kind": "broker" });
    let r = h.put_model("plain", plain).await;
    assert_eq!(r.status_code(), 400);
    assert_eq!(code(&r), "invalid_broker");
}

#[tokio::test]
async fn broker_key_seals_as_bearer_or_named_header() {
    let h = setup().await;
    let mut body = broker_body("https://b.example", json!({}));
    body["auth"] = json!({ "kind": "none" });
    h.put_model("pool", body).await.assert_status_ok();
    let r = h.seal("pool", "first-key").await;
    let got: Value = h
        .op_req(axum::http::Method::GET, "/models/pool")
        .await
        .json();
    assert_eq!(
        got["auth"],
        json!({ "kind": "stored_bearer", "secret_ref": r })
    );
    let resp = h
        .op_req(axum::http::Method::PUT, "/models/pool/credential")
        .json(&json!({ "value": "second-key", "header": "X-Pool-Key" }))
        .await;
    resp.assert_status_ok();
    let text = resp.text();
    assert!(!text.contains("second-key"), "value never echoed");
    let got: Value = h
        .op_req(axum::http::Method::GET, "/models/pool")
        .await
        .json();
    assert_eq!(got["auth"]["kind"], "stored_header");
    assert_eq!(got["auth"]["header"], "X-Pool-Key");
    let clash = h
        .op_req(axum::http::Method::PUT, "/models/pool/credential")
        .json(&json!({ "value": "k", "header": "X-Locksmith-Agent" }))
        .await;
    assert_eq!(clash.status_code(), 400);
    assert_eq!(code(&clash), "invalid_broker");
}

#[tokio::test]
async fn broker_put_without_auth_keeps_the_key() {
    let h = setup().await;
    let mut body = broker_body("https://broker.example", json!({}));
    body.as_object_mut().unwrap().remove("auth");
    h.put_model("pool", body.clone()).await.assert_status_ok();
    let got: Value = h
        .op_req(axum::http::Method::GET, "/models/pool")
        .await
        .json();
    assert_eq!(
        got["auth"],
        json!({ "kind": "none" }),
        "a new broker starts keyless"
    );

    let sref = h.seal("pool", "broker-key-1").await;
    body["broker"] = json!({ "health": { "path": "/v2/healthz" } });
    h.put_model("pool", body).await.assert_status_ok();
    let got: Value = h
        .op_req(axum::http::Method::GET, "/models/pool")
        .await
        .json();
    assert_eq!(
        got["auth"],
        json!({ "kind": "stored_bearer", "secret_ref": sref }),
        "an edit without auth keeps the sealed key"
    );
    assert_eq!(got["broker"]["health"]["path"], "/v2/healthz");

    let plain = upstream_body("https://plain.example");
    let mut no_auth = plain.clone();
    no_auth.as_object_mut().unwrap().remove("auth");
    let r = h.put_model("plain", no_auth).await;
    assert_eq!(code(&r), "auth_required", "only a broker may omit auth");
}
