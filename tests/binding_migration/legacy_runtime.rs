use super::{
    fixture::*,
    inventory::{add, row},
    legacy_contracts::*,
    runtime::{application, call},
};
use agent_locksmith::{registrations::AuthSpec, secret::CredentialSealingKey};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test]
async fn lossy_legacy_mapping_denies_without_dispatch_and_other_mappings_still_work() {
    let f = Fixture::new().await;
    let upstream = MockServer::start().await;
    route(&f, &upstream).await;
    let config = write(&f, &yaml("Authorization", "MIGRATION_X", Some("Bearer ")));
    let mut p = preview(&f, &config);
    assert_eq!(row(&p, f.ids[0], "api")["action"], "skip");
    let other = p["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["agent_id"] == f.ids[0] && e["registration"] == "other")
        .unwrap();
    assert_eq!(other["action"], "propose");
    other["selected"] = true.into();
    success(&apply(&f, &p, &config));
    let server = application(&f.pool, &CredentialSealingKey::generate().unwrap()).await;
    let denied = call(&server, &f, 0, "api").await;
    assert_eq!(denied.status_code().as_u16(), 403);
    assert_eq!(
        denied.json::<serde_json::Value>()["error"]["code"],
        "tool_not_allowed"
    );
    assert!(upstream.received_requests().await.unwrap().is_empty());
    let allowed = call(&server, &f, 0, "other").await;
    allowed.assert_status_ok();
    assert_eq!(allowed.text(), "nonconflicting-route");
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
    assert!(f.bindings.get(f.ids[0], "api").await.unwrap().is_none());
}
async fn route(f: &Fixture, upstream: &MockServer) {
    let mut r = f.registrations.get("api").await.unwrap().unwrap();
    r.upstream = upstream.uri();
    r.auth = AuthSpec::Header {
        header: "Authorization".into(),
        env_var: "MIGRATION_X".into(),
    };
    f.registrations.upsert(&r).await.unwrap();
    add(f, "other", AuthSpec::None).await;
    let mut other = f.registrations.get("other").await.unwrap().unwrap();
    other.upstream = upstream.uri();
    f.registrations.upsert(&other).await.unwrap();
    Mock::given(method("GET"))
        .and(path("/check"))
        .respond_with(ResponseTemplate::new(200).set_body_string("nonconflicting-route"))
        .mount(upstream)
        .await;
}
