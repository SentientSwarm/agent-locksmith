use crate::native_authority::{Error, Result};
use serde_json::{Map, Value};

pub(super) enum Input {
    Search {
        query: String,
        limit: usize,
        cursor: Option<String>,
    },
    Describe(String),
    Invoke {
        handle: String,
        digest: String,
        arguments: Value,
    },
}
impl Input {
    pub fn parse(name: &str, value: Value) -> Result<Self> {
        let o = value.as_object().ok_or(Error("compact_arguments"))?;
        match name {
            "search" => {
                fields(o, &["query", "limit", "cursor"])?;
                let query = o
                    .get("query")
                    .and_then(Value::as_str)
                    .filter(|s| {
                        !s.trim().is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
                    })
                    .ok_or(Error("compact_arguments"))?;
                let limit = match o.get("limit") {
                    None => 5,
                    Some(v) => v
                        .as_u64()
                        .filter(|n| (1..=20).contains(n))
                        .ok_or(Error("compact_arguments"))? as usize,
                };
                let cursor = o.get("cursor").map(|v| reference(v, 32)).transpose()?;
                Ok(Self::Search {
                    query: query.into(),
                    limit,
                    cursor,
                })
            }
            "describe" => {
                fields(o, &["handle"])?;
                Ok(Self::Describe(reference(&value["handle"], 32)?))
            }
            "invoke" => {
                fields(o, &["handle", "contract_digest", "arguments"])?;
                let handle = reference(&value["handle"], 32)?;
                let digest = reference(&value["contract_digest"], 64)?;
                if !value["arguments"].is_object() {
                    return Err(Error("compact_arguments"));
                }
                Ok(Self::Invoke {
                    handle,
                    digest,
                    arguments: value["arguments"].clone(),
                })
            }
            _ => Err(Error("tool_not_approved")),
        }
    }
}
fn fields(o: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    if o.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(Error("compact_arguments"))
    }
}
fn reference(v: &Value, n: usize) -> Result<String> {
    v.as_str()
        .filter(|s| {
            s.len() == n
                && s.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
        .map(str::to_owned)
        .ok_or(Error("compact_arguments"))
}
