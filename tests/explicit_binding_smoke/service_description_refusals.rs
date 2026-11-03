use super::{Fixture, Value, authority, json, process};

pub(super) fn exercise(f: &Fixture, agent: &str) {
    legacy_shapes(f, agent);
    let mut metadata: Value =
        serde_json::from_str(include_str!("../../examples/http-service-reference.json")).unwrap();
    metadata["private"] = json!({"upstream":"private-marker", "account":"private-marker"});
    assert!(put(f, &metadata).status.success());
    let before = f.op(&["tool", "get", "accounts"]);
    let auth_before = authority(f, agent);
    for member in [
        Value::Null,
        json!({"mode":"private-marker"}),
        json!({"version":2}),
    ] {
        let output = put(f, &json!({"http_service":member}));
        assert_eq!(output.status.code(), Some(1));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("invalid_http_service") && !error.contains("private-marker"));
        assert_eq!(f.op(&["tool", "get", "accounts"]), before);
        assert_eq!(authority(f, agent), auth_before);
    }
    file_errors(f);
    assert_eq!(f.op(&["tool", "get", "accounts"]), before);
    assert_eq!(authority(f, agent), auth_before);
}

fn legacy_shapes(f: &Fixture, agent: &str) {
    let before = authority(f, agent);
    for metadata in [
        json!("historical"),
        json!([1, 2]),
        json!({"private":"private-marker"}),
    ] {
        assert!(put(f, &metadata).status.success());
        assert_eq!(f.op(&["tool", "get", "accounts"])["metadata"], metadata);
        assert_eq!(authority(f, agent), before);
    }
}

fn put(f: &Fixture, metadata: &Value) -> std::process::Output {
    let file = f.path().join("service-metadata.json");
    std::fs::write(&file, metadata.to_string()).unwrap();
    process::run(f.cli(&[
        "tool",
        "put",
        "accounts",
        "--upstream",
        &f.upstream,
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
        "--metadata-file",
        file.to_str().unwrap(),
    ]))
}

fn file_errors(f: &Fixture) {
    let file = f.path().join("bad-metadata.json");
    for contents in [None, Some("private-marker bad JSON")] {
        if let Some(contents) = contents {
            std::fs::write(&file, contents).unwrap();
        }
        let output = process::run(f.cli(&[
            "tool",
            "put",
            "accounts",
            "--upstream",
            &f.upstream,
            "--auth",
            "none",
            "--metadata-file",
            file.to_str().unwrap(),
        ]));
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-marker"));
    }
    conflicting_flags(f, &file);
}

fn conflicting_flags(f: &Fixture, file: &std::path::Path) {
    let output = process::run(f.cli(&[
        "tool",
        "put",
        "accounts",
        "--upstream",
        &f.upstream,
        "--metadata-file",
        file.to_str().unwrap(),
        "--metadata",
        "old=value",
    ]));
    assert_eq!(
        output.status.code(),
        Some(2),
        "metadata modes must be exclusive"
    );
}
