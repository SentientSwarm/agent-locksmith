use agent_locksmith::native_authority::{contract, protected};
use serde_json::{Value, json};

fn tool(property: Value) -> Value {
    json!({"name":"invented_read","inputSchema":{"type":"object","properties":{"choice":property},"additionalProperties":false}})
}
fn review(tool: Value) -> Value {
    json!({"tool":tool,"context":{},"effect":"read","retry":"never","contract_policy":"finite-v2"})
}
fn choices(n: usize) -> Value {
    json!({"type":"string","enum":(0..n).map(|i|format!("choice-{i}")).collect::<Vec<_>>()})
}
#[test]
fn policy_v1_positive_and_unknown_policy_refusal() {
    let t = tool(json!({"type":"boolean"}));
    let old = contract::review(&t,"read").unwrap();
    assert_eq!(old,json!({"tool":t,"context":{},"effect":"read","retry":"never"}));
    protected::load(&old).unwrap();
    let mut unknown=review(t); unknown["contract_policy"]="finite-v999".into();
    assert!(protected::load(&unknown).is_err());
    assert!(contract::tool(&tool(choices(17))).is_err());
}
#[test]
fn policy_metadata_original_and_digest_retained() {
    let mut t=tool(json!({"type":"boolean"}));
    t["_meta"]=json!({"invented":["https://invalid.example/inert"]});
    let value=review(t.clone());
    let r=protected::load(&value).unwrap();
    assert_eq!(r.full,t);
    assert_eq!(r.public["_meta"]["invented"],t["_meta"]["invented"]);
    let mut changed=value.clone();changed["tool"]["_meta"]["invented"]=json!(["different"]);
    assert_ne!(contract::digest("locksmith-native-contract-v1",&value),contract::digest("locksmith-native-contract-v1",&changed));
    for meta in [json!(null),json!("x"),json!({"long":"x".repeat(4097)}),json!({"many":vec![0;129]})] {
        let mut bad=value.clone();bad["tool"]["_meta"]=meta;assert!(protected::load(&bad).is_err());
    }
    let mut deep=json!(0);for _ in 0..9 {deep=json!([deep]);}
    let mut bad=value.clone();bad["tool"]["_meta"]=json!({"deep":deep});assert!(protected::load(&bad).is_err());
    let mut bad=value;bad["tool"]["unknown"]=json!({});assert!(protected::load(&bad).is_err());
    assert!(contract::screen(&json!({"_meta":{"synthetic-secret":"safe"}}),"synthetic-secret").is_err());
}
#[test]
fn policy_defaults_are_validated_annotations_never_injected() {
    let t=tool(json!({"type":"integer","minimum":1,"maximum":5,"default":3}));
    let r=protected::load(&review(t.clone())).unwrap();
    assert_eq!(r.full,t);
    assert_eq!(protected::merge(&r,&json!({})).unwrap(),json!({}));
    assert_eq!(protected::merge(&r,&json!({"choice":4})).unwrap(),json!({"choice":4}));
    assert!(protected::merge(&r,&json!({"choice":6})).is_err());
    let mut required=t.clone();required["inputSchema"]["required"]=json!(["choice"]);
    assert!(protected::merge(&protected::load(&review(required)).unwrap(),&json!({})).is_err());
    for p in [json!({"type":"integer","default":true}),json!({"type":"integer","minimum":1,"default":0}),json!({"type":"string","enum":["a"],"default":"b"}),json!({"type":"object","properties":{},"additionalProperties":false,"default":{}})] {
        assert!(protected::load(&review(tool(p))).is_err());
    }
}
#[test]
fn policy_enum_64_and_exact_membership() {
    for n in [45,64] {
        let r=protected::load(&review(tool(choices(n)))).unwrap();
        assert!(protected::merge(&r,&json!({"choice":format!("choice-{}",n-1)})).is_ok());
        assert!(protected::merge(&r,&json!({"choice":"absent"})).is_err());
    }
    for p in [choices(65),choices(0),json!({"type":"string","enum":["a","a"]}),json!({"type":"string","enum":["a",1]})] {
        assert!(protected::load(&review(tool(p))).is_err());
    }
}
#[test]
fn policy_open_empty_input_is_separate_explicit_restriction() {
    let t=json!({"name":"invented_empty","inputSchema":{"type":"object","properties":{}}});
    assert!(contract::tool(&t).is_err());
    assert!(protected::load(&review(t.clone())).is_err(),"restriction must be explicit");
    let mut value=review(t.clone());value["input_restriction"]="empty-arguments".into();
    let r=protected::load(&value).unwrap();
    assert_eq!(r.full,t);
    assert_eq!(r.public["inputSchema"],json!({"type":"object","properties":{},"additionalProperties":false}));
    assert_eq!(protected::merge(&r,&json!({})).unwrap(),json!({}));
    assert!(protected::merge(&r,&json!({"unexpected":true})).is_err());
    let response=protected::response(value.clone()).unwrap();
    assert_eq!(response["callable_input_schema"],r.public["inputSchema"]);
    value["context"]=json!({"unexpected":true});assert!(protected::load(&value).is_err());
    for schema in [json!({"type":"object","properties":{"x":{"type":"string"}}}),json!({"type":"object","properties":{},"additionalProperties":true}),json!({"type":"object","properties":{},"additionalProperties":{}})] {
        let mut bad=review(t.clone());bad["tool"]["inputSchema"]=schema;bad["input_restriction"]="empty-arguments".into();assert!(protected::load(&bad).is_err());
    }
    let mut output=review(tool(json!({"type":"boolean"})));
    output["tool"]["outputSchema"]=t["inputSchema"].clone();assert!(protected::load(&output).is_err());
}
