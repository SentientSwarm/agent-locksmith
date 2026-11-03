use agent_locksmith::registrations::{RegistrationError, http_service::from_metadata};
use serde_json::{Value, json};

fn reference() -> Value {
    serde_json::from_str(include_str!("../examples/http-service-reference.json")).unwrap()
}

fn customer() -> Value {
    serde_json::from_str(include_str!("../examples/http-service-customer.json")).unwrap()
}

fn rejected(metadata: Value) {
    let error = from_metadata(&metadata).unwrap_err();
    assert!(matches!(error, RegistrationError::InvalidHttpService));
    assert!(!error.to_string().contains("private-marker"));
}

#[test]
fn public_examples_describe_actual_response_types() {
    let r = serde_json::to_value(from_metadata(&reference()).unwrap().unwrap()).unwrap();
    assert_eq!(r["operations"][0]["response"]["content_type"], "text/plain");
    assert_eq!(r["operations"][0]["path"], "/check");
    let c = serde_json::to_value(from_metadata(&customer()).unwrap().unwrap()).unwrap();
    assert_eq!(
        c["operations"][0]["response"]["content_type"],
        "application/json"
    );
    assert_eq!(c["operations"][0]["example"]["query"]["limit"], "2");
}

#[test]
fn legacy_shapes_and_private_neighbors_are_not_projected() {
    for legacy in [
        Value::Null,
        json!(4),
        json!("old"),
        json!([]),
        json!({"old":true}),
    ] {
        assert!(from_metadata(&legacy).unwrap().is_none());
    }
    let mut metadata = reference();
    metadata["private"] = json!({"upstream":"private-marker", "account":"private-marker"});
    let projected = serde_json::to_value(from_metadata(&metadata).unwrap().unwrap()).unwrap();
    assert!(!projected.to_string().contains("private-marker"));
    rejected(json!({"http_service": null}));
    rejected(json!({"http_service": "private-marker"}));
}

#[test]
fn unsupported_versions_modes_and_types_are_rejected() {
    for (pointer, value) in [
        ("/http_service/version", json!(2)),
        ("/http_service/version", json!("1")),
        ("/http_service/mode", json!("websocket")),
        ("/http_service/operations/0/method", json!("EXEC")),
        ("/http_service/operations/0/response/status", json!(401)),
        (
            "/http_service/operations/0/response/content_type",
            json!("text/event-stream"),
        ),
        ("/http_service/operations/0/query/0/type", json!("script")),
        ("/http_service/operations/0/query/0/required", json!("yes")),
        (
            "/http_service/operations/0/example/query",
            json!({"unknown":"private-marker"}),
        ),
    ] {
        let mut metadata = customer();
        *metadata.pointer_mut(pointer).unwrap() = value;
        rejected(metadata);
    }
}

#[test]
fn unknown_fields_are_not_public_escape_hatches() {
    for pointer in [
        "/http_service",
        "/http_service/operations/0",
        "/http_service/operations/0/response",
    ] {
        let mut metadata = customer();
        metadata.pointer_mut(pointer).unwrap()["auth"] = json!("private-marker");
        rejected(metadata);
    }
}

#[test]
fn enum_fields_require_strings_not_tagged_objects() {
    for (pointer, value) in [
        ("/http_service/mode", json!({"request_response":null})),
        ("/http_service/operations/0/method", json!({"GET":null})),
        (
            "/http_service/operations/0/query/0/type",
            json!({"integer":null}),
        ),
        (
            "/http_service/operations/0/response/content_type",
            json!({"application/json":null}),
        ),
    ] {
        let mut metadata = customer();
        *metadata.pointer_mut(pointer).unwrap() = value;
        rejected(metadata);
    }
}

#[test]
fn paths_cannot_escape_the_named_registration() {
    for path in [
        "",
        "/",
        "https://private-marker",
        "//private-marker",
        "/../other",
        "/a/./b",
        "/%2e%2e/other",
        "/a?key=private-marker",
        "/a#private-marker",
        "/a\\b",
        "/a/{id}",
        "/a\nb",
    ] {
        let mut metadata = reference();
        metadata["http_service"]["operations"][0]["path"] = json!(path);
        rejected(metadata);
    }
}

#[test]
fn text_response_and_request_examples_are_typed() {
    let mut metadata = reference();
    metadata["http_service"]["operations"][0]["example"]["response"] = json!({"not":"text"});
    rejected(metadata);
    let mut metadata = customer();
    let op = &mut metadata["http_service"]["operations"][0];
    op["method"] = json!("POST");
    op["request_body"] = json!({"required":true,"content_type":"application/json",
        "fields":[{"name":"title","type":"string","required":true,"description":"Job title"}]});
    rejected(metadata.clone());
    metadata["http_service"]["operations"][0]["example"]["body"] =
        json!({"title":"public example"});
    assert!(from_metadata(&metadata).unwrap().is_some());
    metadata["http_service"]["operations"][0]["request_body"]["content_type"] = json!("text/plain");
    rejected(metadata);
}

#[test]
fn duplicates_empty_operations_and_bounds_are_rejected() {
    let mut metadata = customer();
    let op = metadata["http_service"]["operations"][0].clone();
    metadata["http_service"]["operations"] = json!([op, op]);
    rejected(metadata.clone());
    metadata["http_service"]["operations"] = json!([]);
    rejected(metadata);
    let mut metadata = customer();
    let field = metadata["http_service"]["operations"][0]["query"][0].clone();
    metadata["http_service"]["operations"][0]["query"] = json!([field, field]);
    rejected(metadata);
    let mut metadata = reference();
    metadata["http_service"]["operations"][0]["summary"] = json!("a".repeat(2049));
    rejected(metadata);
    let mut metadata = reference();
    metadata["http_service"]["operations"][0]["example"]["response"] = json!("a".repeat(65536));
    rejected(metadata);
}
