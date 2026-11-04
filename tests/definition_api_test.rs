#[path = "definitions/fixture.rs"]
mod fixture;
use fixture::{Fixture, definition, instance, path};
use serde_json::Value;

#[tokio::test]
async fn immutable_definition_creates_only_a_disabled_pinned_instance() {
    let f = Fixture::new().await;
    let d = definition();
    let imported = f.import(&d).await;
    assert_eq!(imported.status_code(), 201);
    let imported: Value = imported.json();
    f.import(&d).await.assert_status_ok();
    let got = f
        .server
        .get(&path(&d))
        .add_header("authorization", &f.token)
        .await;
    assert_eq!(got.json::<Value>()["definition"], d);
    let response = f.create("customer", &instance()).await;
    assert_eq!(response.status_code(), 201);
    let value: Value = response.json();
    assert_eq!(value["disabled"], true);
    assert_eq!(value["mcp"]["definition"]["digest"], imported["digest"]);
    assert_eq!(value["activation"], "disabled");
    assert!(f.repo.get("customer").await.unwrap().unwrap().disabled);
}

#[path = "definitions/credential.rs"]
mod credential;
#[path = "definitions/guards.rs"]
mod guards;
#[path = "definitions/storage.rs"]
mod storage;
