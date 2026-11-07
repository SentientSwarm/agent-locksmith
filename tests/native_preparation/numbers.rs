use agent_locksmith::native_authority::schema;
use serde_json::{Value, json};

fn check(kind: &str, minimum: Value, maximum: Value, supported: bool) {
    let value = json!({"type":"object","additionalProperties":false,"properties":{
        "count":{"type":kind,"minimum":minimum,"maximum":maximum}
    }});
    assert_eq!(schema::root(&value).is_ok(), supported, "{value}");
}

#[test]
fn integer_range_order_preserves_all_sixty_four_bits() {
    for (a, b) in [
        (json!(9007199254740993u64), json!(9007199254740992u64)),
        (json!(u64::MAX), json!(u64::MAX - 1)),
        (json!(-9007199254740992i64), json!(-9007199254740993i64)),
        (json!(i64::MIN + 1), json!(i64::MIN)),
        (json!(u64::MAX), json!(i64::MIN)),
    ] {
        for kind in ["integer", "number"] {
            check(kind, a.clone(), b.clone(), false);
            check(kind, b.clone(), a.clone(), true);
            check(kind, a.clone(), a.clone(), true);
        }
    }
}

#[test]
fn mixed_numeric_range_order_preserves_integer_and_fraction() {
    for (a, b) in [
        (json!(9007199254740993u64), json!(9007199254740992.0)),
        (json!(-9007199254740992.0), json!(-9007199254740993i64)),
        (json!(18446744073709551616.0), json!(u64::MAX)),
        (json!(i64::MAX), json!(9223372036854774784.0)),
        (json!(1.5), json!(1)),
        (json!(-1), json!(-1.5)),
        (json!(0), json!(-0.5)),
        (json!(0.5), json!(0)),
        (json!(1e100), json!(u64::MAX)),
        (json!(i64::MIN), json!(-1e100)),
    ] {
        check("number", a.clone(), b.clone(), false);
        check("number", b, a, true);
    }
}

#[test]
fn finite_float_and_equal_mixed_ranges_stay_supported() {
    for (a, b) in [
        (json!(7), json!(7.0)),
        (json!(-7.0), json!(-7)),
        (json!(0), json!(-0.0)),
        (json!(i64::MIN), json!(-9223372036854775808.0)),
    ] {
        check("number", a.clone(), b.clone(), true);
        check("number", b, a, true);
    }
    check("number", json!(-1.5), json!(2.5), true);
    check("number", json!(2.5), json!(-1.5), false);
}
