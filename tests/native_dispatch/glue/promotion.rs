//! Setup-only pin/promotion adapter; original S3 assertions remain unchanged.
use crate::support::Setup;
use agent_locksmith::{
    definitions,
    registrations::{
        AuthSpec,
        api::{self, AdminRegistrationsState},
    },
    repo::CredentialSecretsRepository,
    secret::CredentialSealingKey,
};
use serde_json::{Value, json};
pub async fn prepare(s: &mut Setup, mechanism: &str) {
    let old = s.f.repo.get("native").await.unwrap().unwrap();
    s.f.repo.delete("native").await.unwrap();
    let state = AdminRegistrationsState {
        broker_health: Default::default(),
        consent: s.rt.consent.clone(),
        local_listener: None,
        repo: s.f.repo.clone(),
        catalog: Some(s.f.catalog.clone()),
        resolved_creds: None,
        credential_sealing_key: None,
        credential_secrets: None,
        operational_log: None,
        op_resolver: None,
        agent_creds: Some(s.f.bindings.clone()),
    };
    let router = definitions::api::router()
        .route("/tools/{name}", axum::routing::get(api::op_get_tool))
        .with_state(state);
    let server = axum_test::TestServer::new(router);
    let mut d: Value =
        serde_json::from_str(include_str!("../../../definitions/customer.example.json")).unwrap();
    d["auth_profiles"][0]["mechanism"] = json!(mechanism);
    d["auth_profiles"][0]["required_scopes"] = if mechanism == "oauth_provider" {
        json!(["read"])
    } else {
        json!([])
    };
    server
        .put("/integration-definitions/local.customer/revisions/1")
        .json(&d)
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    server.post("/tools/native/from-definition").json(&json!({"definition":{"id":"local.customer","revision":1},"auth_profile_id":"none","upstream":old.upstream,"allow_private_destination":true})).await.assert_status(axum::http::StatusCode::CREATED);
    let view: Value = server.get("/tools/native").await.json();
    let mut body = json!({"enabled":true,"compact":crate::COMPACT});
    if mechanism == "oauth_provider" {
        body["oauth_profile_id"] = json!("controlled");
    }
    server
        .put("/tools/native/definition-activation")
        .add_header(
            "if-match",
            view["definition_control"]["revision"].as_str().unwrap(),
        )
        .json(&body)
        .await
        .assert_status_ok();
    s.f.agents
        .update_policy(
            &s.agent,
            Some(Some(vec!["native".into()])),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    if mechanism == "none" {
        s.f.bindings
            .set(s.f.agent_id, "native", &AuthSpec::None)
            .await
            .unwrap();
    }
    if mechanism == "bearer" {
        let key = CredentialSealingKey::generate().unwrap();
        let (ct, nonce) = key.seal(b"fixture-account-x").unwrap();
        let repo = CredentialSecretsRepository::new(s.f.pool.clone());
        let reference = repo.insert(&ct, &nonce).await.unwrap();
        s.f.bindings
            .set(
                s.f.agent_id,
                "native",
                &AuthSpec::StoredBearer {
                    secret_ref: reference,
                },
            )
            .await
            .unwrap();
        s.rt.key = Some(key);
    }
    s.f.refresh().await;
}
