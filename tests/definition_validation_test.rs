#[path = "definitions/fixture.rs"]
mod fixture;
use agent_locksmith::definitions::{MAX_BYTES, parse};
use serde_json::{Value, json};
fn rejects(value: &Value) {
    assert!(parse(&serde_json::to_vec(value).unwrap()).is_err());
}

#[test]
fn strict_schema_rejects_unknown_unsupported_and_inconsistent_input() {
    for (pointer, value) in [
        ("/schema_version", json!(2)),
        ("/revision", json!(0)),
        ("/revision", json!(2147483648u64)),
        ("/id", json!("local.")),
        ("/id", json!("builtin.unknown")),
        ("/protocol_profiles", json!(["http"])),
        (
            "/protocol_profiles",
            json!(["mcp_streamable_http", "compact"]),
        ),
        ("/auth_profiles/0/mechanism", json!("oauth_pkce")),
        ("/verification/level", json!("live")),
        ("/verification/verified_at", json!("2026-01-01")),
        ("/name", json!("")),
        ("/summary", json!("control\u{0000}")),
        ("/auth_profiles", json!([])),
        ("/workflows/0/effect", json!("execute")),
        ("/workflows/0/operations", json!([])),
    ] {
        let mut d = fixture::definition();
        *d.pointer_mut(pointer).unwrap() = value;
        rejects(&d);
    }
    unknown_fields();
}

fn unknown_fields() {
    let mut d = fixture::definition();
    d["credentials"] = json!("unexpected");
    rejects(&d);
    d = fixture::definition();
    d["auth_profiles"][0]["value"] = json!("unsupported");
    rejects(&d);
    rejects(&json!([fixture::definition(), fixture::definition()]));
}
#[test]
fn required_nullable_members_and_real_dates_are_distinct() {
    for key in ["verified_at", "source_revision"] {
        let mut d = fixture::definition();
        d["verification"].as_object_mut().unwrap().remove(key);
        rejects(&d);
    }
    let mut d = fixture::definition();
    d["verification"]["level"] = json!("fixture");
    d["verification"]["source_revision"] = json!("abcdef1");
    for date in [
        "2025-02-29",
        "2026-13-01",
        "2026-01-32",
        "0000-01-01",
        "2026-1-01",
        "+026-01-01",
    ] {
        d["verification"]["verified_at"] = json!(date);
        rejects(&d);
    }
    d["verification"]["verified_at"] = json!("2024-02-29");
    assert!(parse(d.to_string().as_bytes()).is_ok());
}
#[test]
fn duplicate_escaped_keys_depth_and_byte_limits_reject() {
    for raw in [
        r#"{"id":"local.a","\u0069d":"local.b"}"#,
        r#"{"verification":{"level":1,"level":2}}"#,
    ] {
        assert!(parse(raw.as_bytes()).is_err());
    }
    assert!(parse(format!("{}0{}", "[".repeat(33), "]".repeat(33)).as_bytes()).is_err());
    let mut bytes = fixture::definition().to_string().into_bytes();
    bytes.resize(MAX_BYTES + 1, b' ');
    assert!(parse(&bytes).is_err());
}
#[test]
fn collection_and_text_bounds_and_duplicate_ids_reject() {
    for (pointer, value) in [
        ("/name", json!("x".repeat(129))),
        ("/setup", json!("x".repeat(4097))),
        ("/limits", json!(["same", "same"])),
        ("/workflows/0/operations", json!(["same", "same"])),
        ("/auth_profiles/0/required_scopes", json!(["same", "same"])),
        ("/auth_profiles/0/id", json!("Upper")),
    ] {
        let mut d = fixture::definition();
        *d.pointer_mut(pointer).unwrap() = value;
        rejects(&d);
    }
    let mut d = fixture::definition();
    let a = d["auth_profiles"][0].clone();
    d["auth_profiles"].as_array_mut().unwrap().push(a);
    rejects(&d);
    let mut d = fixture::definition();
    let w = d["workflows"][0].clone();
    d["workflows"].as_array_mut().unwrap().push(w);
    rejects(&d);
}
#[test]
fn builtins_use_same_parser_and_cannot_be_replaced() {
    for bytes in [
        include_str!("../definitions/linear.json"),
        include_str!("../definitions/slack.json"),
        include_str!("../definitions/context7.json"),
    ] {
        let d = parse(bytes.as_bytes()).unwrap();
        let mut changed = serde_json::to_value(d).unwrap();
        changed["summary"] = json!("replacement");
        rejects(&changed);
    }
}
