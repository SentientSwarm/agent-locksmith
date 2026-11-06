use super::super::{config, contract_tests, token as custody};
use super::*;
use serde_json::{Value, json};

fn profile(slack: bool) -> config::Profile {
    let mut v = contract_tests::declared(false);
    if slack {
        v["contract"]["token_response"] = json!("slack-user-v2");
        v["contract"]["identity"]["response"] = json!("slack-auth-test-v1");
        v["contract"]["scope"]["response_separator"] = json!("space_or_comma");
    }
    serde_json::from_value(v).unwrap()
}
fn root() -> Value {
    json!({"access_token":"invented-access","token_type":"Bearer","scope":"records:read catalog:inspect"})
}
fn accepts(p: &config::Profile, v: &Value) -> bool {
    custody::decode(p, &serde_json::to_vec(v).unwrap()).is_ok()
}
#[test]
fn contract_slack_complete_variants_and_no_partial_fallback() {
    let p = profile(true);
    assert!(accepts(&p, &root()));
    let mut nested = root();
    nested["ok"] = json!(true);
    nested["token_type"] = json!("user");
    nested["team"] = json!({"id":"tenant-example"});
    nested["authed_user"] = json!({"id":"person-example","scope":"catalog:inspect,records:read"});
    assert!(accepts(&p, &nested));
    for value in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"id":"person-example"}),
        json!({"id":"wrong","scope":"catalog:inspect records:read"}),
    ] {
        let mut bad = nested.clone();
        bad["authed_user"] = value;
        assert!(!accepts(&p, &bad));
    }
    nested_conflicts(&p, &nested);
}
#[test]
fn contract_nullable_duplicate_bounds_and_static_errors() {
    for slack in [false, true] {
        let p = profile(slack);
        for key in ["refresh_token", "expires_in"] {
            let mut value = root();
            value[key] = Value::Null;
            assert_eq!(accepts(&p, &value), slack);
            value[key] = json!({"secret-canary":"do-not-report"});
            let error = custody::decode(&p, &serde_json::to_vec(&value).unwrap())
                .err()
                .unwrap();
            assert!(!error.0.contains("canary"));
        }
        assert!(custody::decode(&p, br#"{"access_token":"a","access_token":"b"}"#).is_err());
        let mut value = root();
        value["access_token"] = json!("x".repeat(8192));
        assert!(accepts(&p, &value));
        value["access_token"] = json!("x".repeat(8193));
        assert!(!accepts(&p, &value));
        value = root();
        value["expires_in"] = json!(true);
        assert!(!accepts(&p, &value));
    }
}
#[test]
fn contract_exact_scopes_and_explicit_separator_policy() {
    let mut p = profile(false);
    for (separator, raw, valid) in [
        ("space", "catalog:inspect records:read", true),
        ("space", "catalog:inspect,records:read", false),
        ("comma", "catalog:inspect, records:read", true),
        ("comma", "catalog:inspect records:read", false),
        ("space_or_comma", "catalog:inspect, records:read", true),
        ("space_or_comma", "catalog:inspect,,records:read", false),
        ("space_or_comma", "catalog:inspect\trecords:read", false),
        (
            "space_or_comma",
            "catalog:inspect,records:read,records:read",
            false,
        ),
    ] {
        p.contract.as_mut().unwrap().scope.response_separator = separator.into();
        let mut v = root();
        v["scope"] = json!(raw);
        assert_eq!(accepts(&p, &v), valid, "{separator} {raw}");
    }
    p.contract.as_mut().unwrap().scope.required = vec!["bad,token".into()];
    assert!(validate(&p).is_err());
}
#[test]
fn contract_subject_observation_never_substitutes_expected_values() {
    let p = profile(false);
    let c = p.contract.as_ref().unwrap();
    let good = json!({"workspace_id":"tenant-example","user_id":"person-example"});
    assert_eq!(c.subject.observe(&good, false).unwrap(), c.subject);
    for value in [
        json!({}),
        json!({"workspace_id":"tenant-example","user_id":null}),
        json!({"workspace_id":"tenant-example","user_id":"wrong"}),
    ] {
        assert!(c.subject.observe(&value, false).is_err());
    }
    let service: config::Profile = serde_json::from_value(contract_tests::declared(true)).unwrap();
    let s = &service.contract.as_ref().unwrap().subject;
    assert!(
        s.observe(&json!({"subject_id":"service-example"}), false)
            .is_ok()
    );
    assert!(s.observe(&good, false).is_err());
    assert!(s.echoes(&good).is_err());
    assert!(publication::facts(&p, None).is_err());
    assert!(publication::facts(&p, Some(s)).is_err());
}
#[test]
fn contract_configuration_and_callback_bind_exact_capabilities() {
    let mut p = profile(false);
    let original = p.digest().unwrap();
    p.contract.as_mut().unwrap().client_auth = "none".into();
    assert_ne!(p.digest().unwrap(), original);
    p.contract.as_mut().unwrap().identity.response = "service-principal-v1".into();
    assert!(validate(&p).is_err());
    p = profile(false);
    p.contract.as_mut().unwrap().identity.endpoint = "https://unapproved.test/identity".into();
    assert!(validate(&p).is_err());
}

#[test]
fn contract_callback_route_is_state_bound() {
    let path = "/oauth/callback/custom/customer";
    let mut p = profile(false);
    assert!(
        p.check_callback(None, "callback.example.test", "/oauth/callback")
            .is_err()
    );
    p.contract.as_mut().unwrap().callback = "distinct_redirect".into();
    p.redirect_uri = "https://callback.example.test/oauth/callback/custom/customer".into();
    assert!(validate(&p).is_ok());
    assert!(
        p.check_callback(None, "callback.example.test", path)
            .is_ok()
    );
    assert!(
        p.check_callback(Some("wrong"), "callback.example.test", path)
            .is_err()
    );
    assert!(
        p.check_callback(None, "callback.example.test", "/oauth/callback")
            .is_err()
    );
    let mut other = p.clone();
    other.issuer = "https://other.test".into();
    assert!(super::super::callback_route::validate(&[p, other]).is_err());
}

fn nested_conflicts(p: &config::Profile, nested: &Value) {
    for (path, value) in [
        ("/team/id", json!("wrong")),
        ("/authed_user/access_token", json!("canary")),
        ("/scope", json!("catalog:inspect")),
    ] {
        let mut bad = nested.clone();
        let parts = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
        if parts.len() == 2 {
            bad[parts[0]][parts[1]] = value;
        } else {
            bad[parts[0]] = value;
        }
        assert!(!accepts(p, &bad));
    }
}
