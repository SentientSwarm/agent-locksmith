//! Fixed whole values in the existing immutable review, never an evaluator.
use super::{Error, Result, contract, values};
use serde_json::{Map, Value, json};

pub const PROFILE: &str = "fixed-top-level-v1";
pub struct Reviewed {
    pub full: Value,
    pub public: Value,
    pub context: Map<String, Value>,
}

pub fn create(tool: &Value, effect: &str, context: &Map<String, Value>) -> Result<Value> {
    let mut value = contract::review(tool, effect)?;
    if !context.is_empty() {
        fixed(tool, context)?;
        value["context"] = Value::Object(context.clone());
        value["context_profile"] = PROFILE.into();
        limit(&value)?;
    }
    Ok(value)
}

pub fn load(value: &Value) -> Result<Reviewed> {
    contract::object(
        value,
        &["tool", "context", "context_profile", "effect", "retry"],
    )?;
    let context = value["context"]
        .as_object()
        .ok_or(Error("review_invalid"))?;
    let expected = create(
        &value["tool"],
        value["effect"].as_str().unwrap_or(""),
        context,
    )?;
    if expected != *value {
        return Err(Error("review_invalid"));
    }
    Ok(Reviewed {
        full: value["tool"].clone(),
        public: project(&value["tool"], context)?,
        context: context.clone(),
    })
}

fn fixed(tool: &Value, context: &Map<String, Value>) -> Result<()> {
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
    values::validate(&schema, &Value::Object(context.clone())).map_err(|_| Error("context_invalid"))
}

fn project(tool: &Value, context: &Map<String, Value>) -> Result<Value> {
    let mut public = tool.clone();
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
    contract::tool(&public)?;
    Ok(public)
}

pub fn merge(reviewed: &Reviewed, supplied: &Value) -> Result<Value> {
    let input = supplied.as_object().ok_or(Error("argument_schema"))?;
    if reviewed.context.keys().any(|k| input.contains_key(k)) {
        return Err(Error("protected_argument"));
    }
    values::validate(&reviewed.public["inputSchema"], supplied)?;
    let mut full = input.clone();
    full.extend(reviewed.context.clone());
    let full = Value::Object(full);
    values::validate(&reviewed.full["inputSchema"], &full)?;
    Ok(full)
}

pub fn response(value: Value) -> Result<Value> {
    crate::native::json::parse(value.to_string().as_bytes()).map_err(|_| Error("review_limit"))?;
    let digest = contract::digest("locksmith-native-contract-v1", &value);
    let reviewed = load(&value)?;
    let mut response =
        json!({"contract":value,"contract_digest":digest,"prepared_only":true,"callable":false});
    if !reviewed.context.is_empty() {
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
