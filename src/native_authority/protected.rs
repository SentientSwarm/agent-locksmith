//! Fixed whole values in the existing immutable review, never an evaluator.
use super::{
    Error, Result, contract,
    policy::{PUBLIC_MARKER, Policy},
    schema, values,
};
use serde_json::{Map, Value, json};

pub const PROFILE: &str = "fixed-top-level-v1";
pub struct Reviewed {
    pub full: Value,
    pub public: Value,
    pub context: Map<String, Value>,
    pub policy: Policy,
}

pub fn create(tool: &Value, effect: &str, context: &Map<String, Value>) -> Result<Value> {
    create_with(tool, effect, context, Policy::V1)
}
pub fn create_with(
    tool: &Value,
    effect: &str,
    context: &Map<String, Value>,
    policy: Policy,
) -> Result<Value> {
    if !matches!(effect, "read" | "write" | "mixed") {
        return Err(Error("invalid_effect"));
    }
    contract::tool_with(tool, policy)?;
    let mut value = json!({"tool":tool,"context":{},"effect":effect,"retry":"never"});
    if policy == Policy::V2 {
        value["contract_policy"] = json!(policy);
        if schema::empty_input(&tool["inputSchema"]) {
            value["input_restriction"] = "empty-arguments".into();
        }
    }
    if !context.is_empty() {
        fixed(tool, context, policy)?;
        value["context"] = Value::Object(context.clone());
        value["context_profile"] = PROFILE.into();
        limit(&value)?;
    }
    Ok(value)
}

pub fn load(value: &Value) -> Result<Reviewed> {
    contract::object(
        value,
        &[
            "tool",
            "context",
            "context_profile",
            "effect",
            "retry",
            "contract_policy",
            "input_restriction",
        ],
    )?;
    let context = value["context"]
        .as_object()
        .ok_or(Error("review_invalid"))?;
    let policy = value
        .get("contract_policy")
        .map(|v| serde_json::from_value(v.clone()).map_err(|_| Error("review_invalid")))
        .transpose()?
        .unwrap_or_default();
    let expected = create_with(
        &value["tool"],
        value["effect"].as_str().unwrap_or(""),
        context,
        policy,
    )?;
    if expected != *value {
        return Err(Error("review_invalid"));
    }
    Ok(Reviewed {
        full: value["tool"].clone(),
        public: project(value, context, policy)?,
        context: context.clone(),
        policy,
    })
}

fn fixed(tool: &Value, context: &Map<String, Value>, policy: Policy) -> Result<()> {
    let properties = tool["inputSchema"]["properties"]
        .as_object()
        .ok_or(Error("context_invalid"))?;
    let mut selected = Map::new();
    for key in context.keys() {
        selected.insert(
            key.clone(),
            properties.get(key).ok_or(Error("context_invalid"))?.clone(),
        );
    }
    let schema = json!({"type":"object","properties":selected,
        "required":context.keys().collect::<Vec<_>>(),"additionalProperties":false});
    values::input(&schema, &Value::Object(context.clone()), policy)
        .map_err(|_| Error("context_invalid"))
}

fn project(review: &Value, context: &Map<String, Value>, policy: Policy) -> Result<Value> {
    let mut public = review["tool"].clone();
    let schema = &mut public["inputSchema"];
    for key in context.keys() {
        schema["properties"]
            .as_object_mut()
            .ok_or(Error("review_invalid"))?
            .remove(key);
    }
    if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
        required.retain(|v| !context.contains_key(v.as_str().unwrap_or("")));
    }
    if review.get("input_restriction").is_some() {
        schema["additionalProperties"] = false.into();
    }
    contract::tool_with(&public, policy)?;
    if policy == Policy::V2 {
        if public.get("_meta").is_none() {
            public["_meta"] = json!({});
        }
        public["_meta"][PUBLIC_MARKER] = json!({"policy":policy,"contract_digest":contract::digest("locksmith-native-contract-v1",review),"input_restriction":review.get("input_restriction"),"schema_origin":if review.get("input_restriction").is_some() || !context.is_empty() {"derived_callable"} else {"provider"}});
    }
    Ok(public)
}

pub fn merge(reviewed: &Reviewed, supplied: &Value) -> Result<Value> {
    let input = supplied.as_object().ok_or(Error("argument_schema"))?;
    if reviewed.context.keys().any(|k| input.contains_key(k)) {
        return Err(Error("protected_argument"));
    }
    values::input(&reviewed.public["inputSchema"], supplied, reviewed.policy)?;
    let mut full = input.clone();
    full.extend(reviewed.context.clone());
    let full = Value::Object(full);
    values::input(&reviewed.full["inputSchema"], &full, reviewed.policy)?;
    Ok(full)
}

pub fn response(value: Value) -> Result<Value> {
    crate::native::json::parse(value.to_string().as_bytes()).map_err(|_| Error("review_limit"))?;
    let digest = contract::digest("locksmith-native-contract-v1", &value);
    let reviewed = load(&value)?;
    let mut response =
        json!({"contract":value,"contract_digest":digest,"prepared_only":true,"callable":false});
    if !reviewed.context.is_empty() || response["contract"].get("input_restriction").is_some() {
        response["callable_input_schema"] = reviewed.public["inputSchema"].clone();
        limit(&response)?;
    }
    Ok(response)
}

fn limit(value: &Value) -> Result<()> {
    if value.to_string().len() > 64 * 1024 {
        Err(Error("review_limit"))
    } else {
        Ok(())
    }
}
