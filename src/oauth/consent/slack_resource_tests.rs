use super::*;

#[test]
fn slack_advertised_resource_accepts_distinct_transport() {
    let mut p = profile();
    p.resource = "https://mcp.slack.com".into();
    assert!(
        slack::validate(&p).is_ok(),
        "advertised resource is the issuer, not /mcp"
    );
}

#[test]
fn slack_resource_and_transport_are_not_interchangeable() {
    let p = profile();
    assert_eq!(p.mcp_endpoint(), "https://mcp.slack.com/mcp");
    for resource in [
        "https://mcp.slack.com/mcp",
        "https://mcp.slack.com/",
        "https://mcp.slack.com?aud=1",
        "https://mcp.slack.com:443",
        "https://foreign.example.test",
    ] {
        let mut bad = p.clone();
        bad.resource = resource.into();
        assert!(slack::validate(&bad).is_err(), "{resource}");
    }
}

#[test]
fn slack_fixture_resource_pair_and_legacy_digest() {
    let mut p = profile();
    p.kind = "slack-confidential-fixture-v1".into();
    p.issuer = "https://127.0.0.1:19293".into();
    p.authorization_endpoint = format!("{}/oauth/v2_user/authorize", p.issuer);
    p.token_endpoint = format!("{}/api/oauth.v2.user.access", p.issuer);
    p.resource = format!("{}/mcp", p.issuer);
    let legacy = serde_json::to_vec(&p).unwrap();
    assert!(slack::validate(&p).is_ok());
    assert_eq!(p.mcp_endpoint(), p.resource);
    assert_eq!(serde_json::to_vec(&p).unwrap(), legacy);
    let old_digest = p.digest().unwrap();
    p.resource = p.issuer.clone();
    assert!(slack::validate(&p).is_ok());
    assert_eq!(p.mcp_endpoint(), format!("{}/mcp", p.issuer));
    assert_ne!(p.digest().unwrap(), old_digest);
    p.resource = "https://127.0.0.1:19294".into();
    assert!(slack::validate(&p).is_err());
}

#[test]
fn slack_resource_echo_is_exact_and_never_endpoint_fallback() {
    let p = profile();
    let mut v = json!({"ok":true,"access_token":"invented-access","token_type":"user","authed_user":{"id":"UTEST001","scope":"channels:history,search:read.public"},"team":{"id":"TTEST001"},"resource":p.resource});
    assert!(slack_token::decode(&p, &v).is_ok());
    for wrong in [
        Value::Null,
        json!(p.mcp_endpoint()),
        json!("https://foreign.example.test"),
    ] {
        v["resource"] = wrong;
        assert!(slack_token::decode(&p, &v).is_err());
    }
}

#[test]
fn slack_fixture_legacy_parsed_spelling_preserves_transport() {
    let mut p = profile();
    p.kind = "slack-confidential-fixture-v1".into();
    p.issuer = "https://127.0.0.1".into();
    p.authorization_endpoint = "https://127.0.0.1:443/oauth/v2_user/authorize".into();
    p.token_endpoint = "https://127.0.0.1:443/api/oauth.v2.user.access".into();
    p.resource = "https://127.0.0.1:443/mcp".into();
    assert!(
        slack::validate(&p).is_ok(),
        "preserve prior parsed-origin predicate"
    );
    assert_eq!(
        p.mcp_endpoint(),
        p.resource,
        "preserve prior transport spelling"
    );
}
