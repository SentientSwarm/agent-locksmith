//! A deliberately finite structural grammar, not a general JSON Schema evaluator.
use super::{
    Error, Result,
    contract::{bounded_text, object, text},
};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub fn root(value: &Value) -> Result<()> {
    if value.get("type").and_then(Value::as_str) != Some("object") {
        return Err(Error("schema_root_object"));
    }
    node(value, 0, &mut 0)
}
fn node(value: &Value, depth: usize, count: &mut usize) -> Result<()> {
    *count += 1;
    if depth > 8 || *count > 128 {
        return Err(Error("schema_limit"));
    }
    let obj = value.as_object().ok_or(Error("schema_object"))?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or(Error("schema_type"))?;
    let mut allowed = vec!["type", "$schema", "title", "description", "enum", "const"];
    allowed.extend_from_slice(fields(kind)?);
    object(value, &allowed)?;
    common(obj, kind)?;
    match kind {
        "object" => properties(obj, depth, count),
        "array" => {
            range(obj, "minItems", "maxItems", true)?;
            node(
                obj.get("items").ok_or(Error("schema_items"))?,
                depth + 1,
                count,
            )
        }
        "string" => range(obj, "minLength", "maxLength", true),
        "integer" | "number" => range(obj, "minimum", "maximum", false),
        _ => Ok(()),
    }
}
fn fields(kind: &str) -> Result<&'static [&'static str]> {
    match kind {
        "object" => Ok(&["properties", "required", "additionalProperties"]),
        "array" => Ok(&["items", "minItems", "maxItems"]),
        "string" => Ok(&["minLength", "maxLength"]),
        "integer" | "number" => Ok(&["minimum", "maximum"]),
        "boolean" | "null" => Ok(&[]),
        _ => Err(Error("schema_type")),
    }
}
fn common(obj: &Map<String, Value>, kind: &str) -> Result<()> {
    if obj
        .get("$schema")
        .is_some_and(|v| v != "https://json-schema.org/draft/2020-12/schema")
    {
        return Err(Error("schema_dialect"));
    }
    for (key, limit) in [("title", 128), ("description", 2048)] {
        if let Some(v) = obj.get(key) {
            bounded_text(v, limit)?;
        }
    }
    choices(obj, kind)
}
fn choices(obj: &Map<String, Value>, kind: &str) -> Result<()> {
    if obj.contains_key("enum") && obj.contains_key("const") {
        return Err(Error("schema_choices"));
    }
    if let Some(v) = obj.get("const") {
        scalar(v, kind)?;
    }
    if let Some(v) = obj.get("enum") {
        let a = v.as_array().ok_or(Error("schema_enum"))?;
        if a.is_empty() || a.len() > 16 {
            return Err(Error("schema_enum"));
        }
        let mut seen = BTreeSet::new();
        for value in a {
            scalar(value, kind)?;
            if !seen.insert(value.to_string()) {
                return Err(Error("schema_enum"));
            }
        }
    }
    Ok(())
}
fn scalar(value: &Value, kind: &str) -> Result<()> {
    let valid = match kind {
        "string" => value.as_str().is_some_and(|v| v.len() <= 2048),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error("schema_choice_type"))
    }
}
fn properties(obj: &Map<String, Value>, depth: usize, count: &mut usize) -> Result<()> {
    if obj.get("additionalProperties") != Some(&Value::Bool(false)) {
        return Err(Error("schema_additional_properties"));
    }
    let props = obj
        .get("properties")
        .and_then(Value::as_object)
        .ok_or(Error("schema_properties"))?;
    for (name, schema) in props {
        text(&Value::String(name.clone()), 128)?;
        node(schema, depth + 1, count)?;
    }
    if let Some(required) = obj.get("required") {
        let required = required.as_array().ok_or(Error("schema_required"))?;
        let mut seen = BTreeSet::new();
        for v in required {
            let name = v.as_str().ok_or(Error("schema_required"))?;
            if !props.contains_key(name) || !seen.insert(name) {
                return Err(Error("schema_required"));
            }
        }
    }
    Ok(())
}
fn range(obj: &Map<String, Value>, low: &str, high: &str, integer: bool) -> Result<()> {
    for key in [low, high] {
        if let Some(v) = obj.get(key)
            && (if integer {
                v.as_u64().is_none()
            } else {
                v.as_f64().is_none()
            })
        {
            return Err(Error("schema_range"));
        }
    }
    if let (Some(a), Some(b)) = (obj.get(low), obj.get(high)) {
        let reversed = if integer {
            a.as_u64() > b.as_u64()
        } else {
            super::numbers::compare(a.as_number().unwrap(), b.as_number().unwrap()).is_gt()
        };
        if reversed {
            return Err(Error("schema_range"));
        }
    }
    Ok(())
}
