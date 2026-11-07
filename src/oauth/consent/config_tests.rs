use super::*;
use serde_json::{Value, json};
fn configuration(kind: &str, origin: &str, redirect: &str) -> Value {
    let mut p = json!({"id":"test", "kind":kind, "client_id":"synthetic-client", "client_generation":1,
        "issuer":origin, "authorization_endpoint":format!("{origin}/authorize"),
        "token_endpoint":format!("{origin}/token"),"resource":format!("{origin}/mcp/readonly"),
        "redirect_profile_id":"callback", "redirect_uri":redirect,
        "expected_workspace":"00000000-0000-0000-0000-000000000041",
        "expected_user":"00000000-0000-0000-0000-000000000042","ca_path":"synthetic-ca.pem"});
    if kind != "controlled-linear-v1" {
        p["selected_tools"] = json!(["get_project", "get_issue"]);
    }
    json!({"callback":{"address":"127.0.0.1:24443","cert_path":"synthetic-cert.pem","key_path":"synthetic-key.pem"},"profiles":[p]})
}
fn valid(v: &Value) -> bool {
    serde_json::from_value::<Config>(v.clone()).is_ok_and(|c| c.validate().is_ok())
}
#[test]
fn hosted_profiles_fixed_endpoints_public_callback_and_explicit_selection() {
    let controlled = configuration(
        "controlled-linear-v1",
        "https://127.0.0.1:24444",
        "https://127.0.0.1:24443/oauth/callback",
    );
    assert!(valid(&controlled), "unchanged controlled positive control");
    let hosted = configuration(
        "linear-hosted-v1",
        "https://mcp.linear.app",
        "https://callback.example.test/oauth/callback",
    );
    assert!(
        valid(&hosted),
        "fixed hosted profile with separately bound public callback"
    );
    let fixture = fixture_profile();
    refused_endpoints(&hosted);
    refused_redirects(&hosted);
    refused_selection(&hosted);
    stable_binding(&controlled, &hosted, &fixture);
}

fn fixture_profile() -> Value {
    let fixture = configuration(
        "linear-hosted-fixture-v1",
        "https://127.0.0.1:24444",
        "https://callback.example.test/oauth/callback",
    );
    assert!(
        valid(&fixture),
        "explicit offline twin uses shipping hosted policy"
    );
    fixture
}

fn refused_endpoints(hosted: &Value) {
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "resource",
    ] {
        let mut wrong = hosted.clone();
        wrong["profiles"][0][field] = json!(format!("https://other.example/{}", field));
        assert!(!valid(&wrong), "{field}");
    }
}

fn refused_redirects(hosted: &Value) {
    for uri in [
        "http://callback.example.test/oauth/callback",
        "https://user@callback.example.test/oauth/callback",
        "https://callback.example.test/oauth/callback?extra=1",
        "https://callback.example.test/other",
    ] {
        let mut wrong = hosted.clone();
        wrong["profiles"][0]["redirect_uri"] = json!(uri);
        assert!(!valid(&wrong));
    }
}

fn refused_selection(hosted: &Value) {
    for names in [
        json!([]),
        json!(["get_project", "get_project"]),
        json!([""]),
        json!(vec!["tool"; 33]),
    ] {
        let mut wrong = hosted.clone();
        wrong["profiles"][0]["selected_tools"] = names;
        assert!(!valid(&wrong));
    }
}

fn stable_binding(controlled: &Value, hosted: &Value, fixture: &Value) {
    let mut wrong = fixture.clone();
    wrong["profiles"][0]["issuer"] = json!("https://mcp.linear.app");
    assert!(!valid(&wrong));
    let mut wrong = controlled.clone();
    wrong["profiles"][0]["redirect_uri"] = json!("https://callback.example.test/oauth/callback");
    assert!(!valid(&wrong));
    let before: Profile = serde_json::from_value(controlled["profiles"][0].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(before).unwrap(),
        controlled["profiles"][0],
        "controlled serialization/digests cannot change"
    );
    let mut changed = hosted.clone();
    changed["profiles"][0]["selected_tools"] = json!(["get_project"]);
    let profile = |v: &Value| serde_json::from_value::<Profile>(v["profiles"][0].clone()).unwrap();
    assert_ne!(
        profile(hosted).digest().unwrap(),
        profile(&changed).digest().unwrap()
    );
    assert_ne!(
        profile(hosted).digest().unwrap(),
        profile(fixture).digest().unwrap()
    );
}
