use agent_locksmith::native_authority::{api, contract, schema, writes};
use serde_json::json;

#[test]
fn finite_schema_and_exact_semantic_contract() {
    let original = super::support::tool("read");
    contract::tool(&original).unwrap();
    for replacement in [
        json!({"type":"string"}),
        json!({"type":"array","items":{"type":"string"}}),
        json!({"type":"object","properties":{},"additionalProperties":true}),
        json!({"type":"object","properties":{},"additionalProperties":false,"$ref":"https://example.com"}),
    ] {
        assert!(schema::root(&replacement).is_err());
    }
    let mut changed = original.clone();
    changed["description"] = "Different reviewed behavior".into();
    assert_ne!(contract::observed(&original), contract::observed(&changed));
    let read = contract::review(&original, "read").unwrap();
    let write = contract::review(&original, "write").unwrap();
    assert_ne!(
        contract::digest("contract", &read),
        contract::digest("contract", &write)
    );
    for key in ["icons", "execution", "_meta"] {
        let mut v = original.clone();
        v[key] = json!({});
        assert!(contract::tool(&v).is_err());
    }
}
#[test]
fn duplicate_nullable_and_escaped_secret_boundaries() {
    assert!(api::parse::<serde_json::Value>(br#"{"a":1,"\u0061":2}"#).is_err());
    let source = json!({"instance":"i","revision":1,"account_key":"a","agent_epoch":1});
    assert!(
        api::parse::<writes::Observe>(json!({"source":source}).to_string().as_bytes()).is_err()
    );
    assert!(
        api::parse::<writes::Observe>(
            json!({"source":source,"generation":null})
                .to_string()
                .as_bytes()
        )
        .is_ok()
    );
    let secret = "synthetic-\"quote\\tail";
    assert!(contract::screen(&json!({"message":secret}), secret).is_err());
    assert!(contract::screen(&json!({secret:"value"}), secret).is_err());
    assert!(contract::screen(&json!({"message":"safe"}), secret).is_ok());
}
#[test]
fn address_policy_pairs_actual_self_port_with_identity() {
    use agent_locksmith::native_authority::destination::approve;
    let local = ["127.0.0.1".parse().unwrap(), "10.1.2.3".parse().unwrap()];
    assert!(approve("8.8.8.8:443".parse().unwrap(), false, &local, &[443]).is_ok());
    assert!(approve("10.1.2.3:443".parse().unwrap(), true, &local, &[443]).is_err());
    assert!(approve("127.0.0.1:8443".parse().unwrap(), true, &local, &[443]).is_ok());
    for ip in [
        "169.254.169.254:80",
        "192.0.2.1:443",
        "[::ffff:127.0.0.1]:443",
        "[2001:db8::1]:443",
    ] {
        assert!(
            approve(ip.parse().unwrap(), true, &local, &[]).is_err(),
            "{ip}"
        );
    }
}
