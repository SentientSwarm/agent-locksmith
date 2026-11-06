//! Execute exactly the finite reviewed grammar; never resolve external schemas.
use super::{Error, Result, numbers, schema};
use serde_json::{Map, Value};

pub fn validate(schema: &Value, value: &Value) -> Result<()> {
    schema::root(schema)?;
    checked(schema, value)
}
pub fn input(schema: &Value, value: &Value, policy: super::policy::Policy) -> Result<()> {
    schema::input(schema, policy)?;
    checked(schema, value)
}
pub(super) fn annotation(schema: &Value, value: &Value) -> Result<()> {
    node(schema, value, 0, &mut 0)
}
fn checked(schema: &Value, value: &Value) -> Result<()> {
    if value.to_string().len() > 32 * 1024 {
        return Err(Error("value_limit"));
    }
    node(schema, value, 0, &mut 0)
}
fn node(s: &Value, v: &Value, depth: usize, count: &mut usize) -> Result<()> {
    *count += 1;
    if depth > 16 || *count > 4096 {
        return Err(Error("value_limit"));
    }
    let valid = match s["type"].as_str() {
        Some("object") => v.is_object(),
        Some("array") => v.is_array(),
        Some("string") => v.is_string(),
        Some("boolean") => v.is_boolean(),
        Some("null") => v.is_null(),
        Some("integer") => v.is_i64() || v.is_u64(),
        Some("number") => v.is_number(),
        _ => false,
    };
    if !valid {
        return Err(Error("argument_schema"));
    }
    choices(s, v)?;
    match v {
        Value::Object(o) => object(s, o, depth, count),
        Value::Array(a) => array(s, a, depth, count),
        Value::String(t) => length(s, t.chars().count(), "minLength", "maxLength"),
        Value::Number(_) => range(s, v),
        _ => Ok(()),
    }
}
fn object(s: &Value, o: &Map<String, Value>, depth: usize, count: &mut usize) -> Result<()> {
    let props = s["properties"]
        .as_object()
        .ok_or(Error("argument_schema"))?;
    for key in s["required"].as_array().into_iter().flatten() {
        if !o.contains_key(key.as_str().ok_or(Error("argument_schema"))?) {
            return Err(Error("argument_schema"));
        }
    }
    for (key, v) in o {
        node(
            props.get(key).ok_or(Error("argument_schema"))?,
            v,
            depth + 1,
            count,
        )?;
    }
    Ok(())
}
fn array(s: &Value, a: &[Value], depth: usize, count: &mut usize) -> Result<()> {
    length(s, a.len(), "minItems", "maxItems")?;
    for v in a {
        node(&s["items"], v, depth + 1, count)?;
    }
    Ok(())
}
fn length(s: &Value, n: usize, min: &str, max: &str) -> Result<()> {
    if s[min].as_u64().is_some_and(|m| (n as u64) < m)
        || s[max].as_u64().is_some_and(|m| (n as u64) > m)
    {
        Err(Error("argument_schema"))
    } else {
        Ok(())
    }
}
fn range(s: &Value, v: &Value) -> Result<()> {
    let n = v.as_number().ok_or(Error("argument_schema"))?;
    if s["minimum"]
        .as_number()
        .is_some_and(|m| numbers::compare(n, m).is_lt())
        || s["maximum"]
            .as_number()
            .is_some_and(|m| numbers::compare(n, m).is_gt())
    {
        Err(Error("argument_schema"))
    } else {
        Ok(())
    }
}
fn equal(a: &Value, b: &Value) -> bool {
    match (a.as_number(), b.as_number()) {
        (Some(a), Some(b)) => numbers::compare(a, b).is_eq(),
        _ => a == b,
    }
}
fn choices(s: &Value, v: &Value) -> Result<()> {
    if s.get("const").is_some_and(|c| !equal(c, v))
        || s["enum"]
            .as_array()
            .is_some_and(|a| !a.iter().any(|c| equal(c, v)))
    {
        Err(Error("argument_schema"))
    } else {
        Ok(())
    }
}
