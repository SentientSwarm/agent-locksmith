use super::*;
use serde_json::json;
fn profile() -> config::Profile {
    serde_json::from_value(json!({"id":"slack","kind":"slack-confidential-v1","client_id":"synthetic-client","client_generation":1,
        "issuer":"https://mcp.slack.com","authorization_endpoint":"https://slack.com/oauth/v2_user/authorize",
        "token_endpoint":"https://slack.com/api/oauth.v2.user.access","resource":"https://mcp.slack.com/mcp",
        "redirect_profile_id":"callback","redirect_uri":"https://callback.example.test/oauth/callback",
        "expected_workspace":"TTEST001","expected_user":"UTEST001","ca_path":"synthetic.pem","selected_tools":[]})).unwrap()
}
#[test]
fn slack_fixed_profile_and_linear_positive() {
    let p = profile();
    let c = config::Config {
        callback: config::Callback {
            address: "127.0.0.1:24443".parse().unwrap(),
            cert_path: "synthetic.pem".into(),
            key_path: "synthetic.key".into(),
        },
        profiles: vec![p.clone()],
    };
    assert!(c.validate().is_ok(), "fixed Slack confidential profile");
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "resource",
    ] {
        let mut v = serde_json::to_value(&p).unwrap();
        v[field] = json!("https://other.example.test/wrong");
        let mut bad = c.clone();
        bad.profiles = vec![serde_json::from_value(v).unwrap()];
        assert!(bad.validate().is_err());
    }
}
#[test]
fn slack_user_token_optional_and_malformed_fields() {
    let p = profile();
    let value = json!({"ok":true,"access_token":"invented-access-value","token_type":"user","authed_user":{"id":"UTEST001","scope":"search:read.public,channels:history"},"team":{"id":"TTEST001"}});
    let decode = |v: &Value| token::decode(&p, &serde_json::to_vec(v).unwrap());
    let t = decode(&value).expect("user-token positive");
    assert!(t.expiry.is_none());
    assert!(t.refresh.is_none());
    let mut nullable = value.clone();
    nullable["expires_in"] = Value::Null;
    nullable["refresh_token"] = Value::Null;
    assert!(decode(&nullable).is_ok());
    malformed(&value, decode);
}

fn malformed(value: &Value, decode: impl Fn(&Value) -> Result<token::Token>) {
    for (path, v) in [
        ("/ok", json!(false)),
        ("/token_type", json!("bot")),
        ("/authed_user/id", json!("UOTHER1")),
        ("/team/id", json!("TOTHER1")),
        ("/authed_user/scope", json!("channels:history")),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(path).unwrap() = v;
        assert!(decode(&bad).is_err(), "{path}");
    }
    for (field, v) in [
        ("expires_in", json!(0)),
        ("expires_in", json!("3600")),
        ("refresh_token", json!(false)),
        ("client_id", json!("wrong")),
    ] {
        let mut bad = value.clone();
        bad[field] = v;
        assert!(decode(&bad).is_err(), "{field}");
    }
}

#[test]
fn slack_closed_response_metadata_and_nested_conflicts() {
    let p = profile();
    let v = json!({"ok":true,"access_token":"invented-access","token_type":"user","authed_user":{"id":"UTEST001","scope":"channels:history,search:read.public"},"team":{"id":"TTEST001"}});
    assert!(slack_token::decode(&p, &v).is_ok());
    for (key, value) in [
        ("access_token", json!("different")),
        ("token_type", json!("bot")),
        ("refresh_token", Value::Null),
        ("expires_in", json!(1)),
    ] {
        let mut bad = v.clone();
        bad["authed_user"][key] = value;
        assert!(slack_token::decode(&p, &bad).is_err(), "nested {key}");
    }
    missing_or_conflicting(&p, &v);
}

fn missing_or_conflicting(p: &config::Profile, v: &Value) {
    for field in ["access_token", "token_type", "team", "authed_user", "ok"] {
        let mut bad = v.clone();
        bad.as_object_mut().unwrap().remove(field);
        assert!(slack_token::decode(p, &bad).is_err(), "missing {field}");
    }
    for scopes in [
        "search:read.public,search:read.public",
        "search:read.public,channels:history,extra",
        " search:read.public,channels:history",
    ] {
        let mut bad = v.clone();
        bad["authed_user"]["scope"] = json!(scopes);
        assert!(slack_token::decode(p, &bad).is_err());
    }
    error_metadata(p);
}

fn error_metadata(p: &config::Profile) {
    assert_eq!(
        slack_token::outcome(&json!({"ok":false,"error":"bad_client_secret"}))
            .unwrap_err()
            .0,
        "slack_client_refused"
    );
    assert_eq!(
        slack_token::outcome(&json!({"ok":false,"error":"private-canary"}))
            .unwrap_err()
            .0,
        "slack_error_response"
    );
    assert!(
        slack_token::decode(
            p,
            &json!({"ok":false,"error":"invalid_code","access_token":"canary"})
        )
        .is_err()
    );
}
