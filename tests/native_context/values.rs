use agent_locksmith::native_authority::{protected, values};
use serde_json::{Value, json};

fn tool() -> Value {
    json!({"name":"lookup","inputSchema":{"type":"object","properties":{
        "workspace":{"type":"string"},"query":{"type":"string"},
        "nested":{"type":"object","properties":{"workspace":{"type":"integer"}},"additionalProperties":false}
    },"required":["workspace","query"],"additionalProperties":false}})
}
fn reviewed(context: Value) -> protected::Reviewed {
    let contract = protected::create(&tool(), "read", context.as_object().unwrap()).unwrap();
    protected::load(&contract).unwrap()
}

#[test]
fn projection_and_merge_preserve_nested_fields_and_refuse_any_override() {
    let r = reviewed(json!({"workspace":"fixed"}));
    let supplied = json!({"query":"read","nested":{"workspace":42}});
    assert_eq!(
        protected::merge(&r, &supplied).unwrap(),
        json!({"workspace":"fixed","query":"read","nested":{"workspace":42}})
    );
    for value in [json!("fixed"), json!("different"), Value::Null] {
        assert_eq!(
            protected::merge(&r, &json!({"workspace":value,"query":"read"}))
                .unwrap_err()
                .0,
            "protected_argument"
        );
    }
    let escaped: Value =
        serde_json::from_str(r#"{"\u0077orkspace":"fixed","query":"read"}"#).unwrap();
    assert_eq!(
        protected::merge(&r, &escaped).unwrap_err().0,
        "protected_argument"
    );
    assert!(protected::merge(&r, &json!({})).is_err());
    assert!(protected::merge(&r, &json!({"query":1})).is_err());
}

#[test]
fn aggregate_bytes_are_checked_after_both_halves_individually_fit() {
    let r = reviewed(json!({"workspace":"x".repeat(17000)}));
    let supplied = json!({"query":"y".repeat(17000)});
    assert!(values::validate(&r.public["inputSchema"], &supplied).is_ok());
    assert_eq!(
        protected::merge(&r, &supplied).unwrap_err().0,
        "value_limit"
    );
}

#[test]
fn unknown_profiles_and_full_tool_substitution_fail_closed() {
    let mut c = protected::create(
        &tool(),
        "read",
        json!({"workspace":"fixed"}).as_object().unwrap(),
    )
    .unwrap();
    c["context_profile"] = "future-profile".into();
    assert!(protected::load(&c).is_err());
    c["context_profile"] = protected::PROFILE.into();
    c["tool"] = protected::load(&c).unwrap().public;
    assert!(protected::load(&c).is_err());
}

#[test]
fn fixed_nested_values_use_exact_numeric_and_unicode_constraints() {
    let mut t = tool();
    t["inputSchema"]["properties"]["nested"]["properties"]["workspace"]["minimum"] =
        json!(9007199254740993u64);
    let good = json!({"nested":{"workspace":9007199254740993u64}});
    assert!(protected::create(&t, "read", good.as_object().unwrap()).is_ok());
    let bad = json!({"nested":{"workspace":9007199254740992u64}});
    assert!(protected::create(&t, "read", bad.as_object().unwrap()).is_err());
    t["inputSchema"]["properties"]["workspace"] =
        json!({"type":"string","minLength":2,"maxLength":2});
    assert!(protected::create(&t, "read", json!({"workspace":"é🌍"}).as_object().unwrap()).is_ok());
    assert!(protected::create(&t, "read", json!({"workspace":"é"}).as_object().unwrap()).is_err());
}
