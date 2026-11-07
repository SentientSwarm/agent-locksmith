use super::{
    super::{config::Profile, contract_tests, token},
    identity_value,
};
use serde_json::{Value, json};
fn profile() -> Profile {
    let mut value = contract_tests::declared(false);
    value["contract"]["token_response"] = json!("slack-user-v2");
    value["contract"]["identity"]["response"] = json!("slack-auth-test-v1");
    serde_json::from_value(value).unwrap()
}
fn identity() -> Value {
    json!({"ok":true,"team":"Invented Workspace","user":"invented-user",
        "url":"https://invented.slack.com/","team_id":"tenant-example","user_id":"person-example"})
}
#[test]
fn documented_identity_display_labels_are_not_authority() {
    let p = profile();
    let value = identity();
    assert_eq!(
        identity_value::decode(&p, &value).unwrap(),
        p.contract.as_ref().unwrap().subject
    );
    let mut changed = value.clone();
    changed["team"] = json!("Different display name");
    changed["user"] = json!("different display name");
    assert_eq!(
        identity_value::decode(&p, &changed).unwrap(),
        p.contract.as_ref().unwrap().subject
    );
    changed.as_object_mut().unwrap().remove("team");
    assert!(identity_value::decode(&p, &changed).is_ok());
}
#[test]
fn identity_ids_and_bot_claims_stay_strict() {
    let p = profile();
    for key in ["team_id", "user_id"] {
        for replacement in [
            Value::Null,
            json!(false),
            json!(""),
            json!("wrong"),
            json!({"id":"canary"}),
        ] {
            let mut value = identity();
            value[key] = replacement;
            assert!(identity_value::decode(&p, &value).is_err());
        }
        let mut value = identity();
        value.as_object_mut().unwrap().remove(key);
        assert!(identity_value::decode(&p, &value).is_err());
    }
}
#[test]
fn identity_bot_claims_stay_strict() {
    let p = profile();
    for (key, value) in [
        ("bot_id", json!(null)),
        ("bot_user_id", json!("bot")),
        ("is_bot", json!(true)),
        ("subject_id", json!("service")),
    ] {
        let mut bad = identity();
        bad[key] = value;
        assert_eq!(
            identity_value::decode(&p, &bad).unwrap_err().0,
            "identity_echo_refused"
        );
    }
}
#[test]
fn identity_closed_reasons_do_not_echo_values() {
    let p = profile();
    for (key, value, expected) in diagnostic_cases() {
        let mut bad = identity();
        bad[key] = value;
        assert_eq!(identity_value::decode(&p, &bad).unwrap_err().0, expected);
    }
    assert_eq!(
        identity_value::decode(&p, &json!([])).unwrap_err().0,
        "identity_response_shape"
    );
}
#[test]
fn token_nested_identity_rules_are_unchanged() {
    let p = profile();
    let token_value = json!({"ok":true,"access_token":"invented-access","token_type":"user",
        "team":{"id":"tenant-example"},"authed_user":{"id":"person-example","scope":"catalog:inspect records:read"}});
    assert!(token::decode(&p, &serde_json::to_vec(&token_value).unwrap()).is_ok());
    for value in [
        json!("Invented Workspace"),
        Value::Null,
        json!({"id":"wrong"}),
    ] {
        let mut bad = token_value.clone();
        bad["team"] = value;
        assert!(token::decode(&p, &serde_json::to_vec(&bad).unwrap()).is_err());
    }
}

fn diagnostic_cases() -> Vec<(&'static str, Value, &'static str)> {
    vec![
        (
            "team",
            json!({"id":"tenant-example"}),
            "identity_team_display_type",
        ),
        ("team", Value::Null, "identity_team_display_type"),
        ("error", json!("private-canary"), "identity_error_present"),
        ("ok", json!(false), "identity_ok_refused"),
        (
            "issuer",
            json!("private-canary"),
            "identity_metadata_refused",
        ),
        (
            "authed_user",
            json!({"id":"wrong-canary"}),
            "identity_echo_refused",
        ),
    ]
}
