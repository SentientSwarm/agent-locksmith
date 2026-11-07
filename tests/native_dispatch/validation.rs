use agent_locksmith::native_authority::{call_result, values};
use serde_json::{Value, json};

fn schema(property: Value) -> Value {
    json!({"type":"object","properties":{"v":property},"required":["v"],"additionalProperties":false})
}
#[test]
fn arguments_enforce_types_unicode_and_closed_nested_objects() {
    for (s, good, bad) in type_cases() {
        let s = schema(s);
        assert!(values::validate(&s, &json!({"v":good})).is_ok());
        assert!(values::validate(&s, &json!({"v":bad})).is_err());
        assert!(values::validate(&s, &json!({})).is_err());
        assert!(values::validate(&s, &json!({"v":good,"extra":true})).is_err());
    }
}
#[test]
fn numeric_choices_and_ranges_preserve_large_integer_identity() {
    let s = schema(
        json!({"type":"number","minimum":9007199254740993_u64,"maximum":9007199254740993_u64}),
    );
    assert!(values::validate(&s, &json!({"v":9007199254740993_u64})).is_ok());
    assert!(values::validate(&s, &json!({"v":9007199254740992_f64})).is_err());
    for choice in ["enum", "const"] {
        let mut p = json!({"type":"number"});
        p[choice] = if choice == "enum" {
            json!([9007199254740993_u64])
        } else {
            json!(9007199254740993_u64)
        };
        assert!(values::validate(&schema(p.clone()), &json!({"v":9007199254740993_u64})).is_ok());
        assert!(values::validate(&schema(p), &json!({"v":9007199254740992_f64})).is_err());
    }
    assert!(
        values::validate(
            &schema(json!({"type":"number","const":1})),
            &json!({"v":1.0})
        )
        .is_ok()
    );
}
#[test]
fn values_have_independent_byte_and_work_limits() {
    let s = schema(json!({"type":"string"}));
    assert_eq!(
        values::validate(&s, &json!({"v":"x".repeat(32769)}))
            .unwrap_err()
            .0,
        "value_limit"
    );
    let s = schema(json!({"type":"array","items":{"type":"null"}}));
    assert_eq!(
        values::validate(&s, &json!({"v":vec![Value::Null;4096]}))
            .unwrap_err()
            .0,
        "value_limit"
    );
}
#[test]
fn results_preserve_tool_error_but_reject_unsupported_or_wrong_output() {
    let tool = json!({"outputSchema":schema(json!({"type":"integer"}))});
    let good = json!({"content":[{"type":"text","text":"done"}],"structuredContent":{"v":1}});
    assert!(call_result::checked(&tool, &good).is_ok());
    assert!(call_result::checked(&tool, &json!({"content":[],"isError":true})).is_ok());
    for bad in [
        json!({"content":[]}),
        json!({"content":[{"type":"image","data":"x","mimeType":"image/png"}]}),
        json!({"content":[],"structuredContent":{"v":"wrong"}}),
        json!({"content":[],"_meta":{}}),
        json!({"content":[],"isError":"false"}),
        json!({"content":[{"type":"text","text":"x".repeat(16385)}]}),
    ] {
        assert!(call_result::checked(&tool, &bad).is_err());
    }
}

fn type_cases() -> [(Value, Value, Value); 6] {
    [
        (
            json!({"type":"string","minLength":2,"maxLength":2}),
            json!("é🌍"),
            json!("é"),
        ),
        (
            json!({"type":"integer","minimum":1,"maximum":2}),
            json!(2),
            json!(2.0),
        ),
        (json!({"type":"boolean"}), json!(true), json!(1)),
        (json!({"type":"null"}), Value::Null, json!(false)),
        (
            json!({"type":"array","items":{"type":"string"},"maxItems":2}),
            json!(["a", "b"]),
            json!(["a", 1]),
        ),
        (
            json!({"type":"object","properties":{},"additionalProperties":false}),
            json!({}),
            json!({"extra":1}),
        ),
    ]
}
