//! AGENT-265 — which output a streamed text field belongs to.
//!
//! A client rebuilds each output of a stream separately: each choice of a
//! chat completion, each tool call by its `index`, each Anthropic content
//! block, each Responses output and content part. A match split across
//! deltas is only contiguous within one output, so each gets its own
//! window (a lane). A lane closes when the protocol says its output is
//! finished, so its last held events need not wait for the stream to end.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

/// One output of a stream: the field's path, with each array position
/// that carries an integer `index` replaced by `#<index>`, and the
/// event's top-level indexes as tags.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Lane {
    pub path: String,
    pub tags: Vec<(&'static str, i64)>,
}

/// Top-level fields that name which output an event belongs to.
const TAGS: [(&str, &str); 3] = [
    ("index", "i"),
    ("output_index", "o"),
    ("content_index", "c"),
];

/// An index as a lenient client reads it: an integer, an integer-valued
/// float, or a string holding one.
fn index(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The tags an event's top-level indexes give.
pub fn tags(value: &Value) -> Vec<(&'static str, i64)> {
    TAGS.iter()
        .filter_map(|(field, tag)| index(value.get(*field)?).map(|n| (*tag, n)))
        .collect()
}

/// The path segment for array element `i`: its `index`, when it has one.
pub fn element(item: &Value, i: usize) -> String {
    match item.get("index").and_then(index) {
        Some(n) => format!("#{n}"),
        None => i.to_string(),
    }
}

/// Which lanes an event finishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Close {
    /// The stream is over (`[DONE]`, `message_stop`, `response.completed`).
    All,
    /// Lanes under this path (a chat choice with a `finish_reason`).
    Under(String),
    /// Lanes carrying every one of these tags (an Anthropic block or a
    /// Responses output finished).
    Tagged(Vec<(&'static str, i64)>),
}

impl Close {
    pub fn covers(&self, lane: &Lane) -> bool {
        match self {
            Close::All => true,
            Close::Under(prefix) => lane.path.starts_with(prefix),
            Close::Tagged(tags) => !tags.is_empty() && tags.iter().all(|t| lane.tags.contains(t)),
        }
    }
}

/// The lanes `value` (an event's `data`, of type `kind`) finishes.
pub fn closes(kind: Option<&str>, value: &Value) -> Vec<Close> {
    let mut out = Vec::new();
    match kind {
        Some("message_stop" | "response.completed" | "response.failed" | "response.incomplete") => {
            out.push(Close::All)
        }
        Some("content_block_stop") => out.push(Close::Tagged(tags(value))),
        Some(k) if k.starts_with("response.") && k.ends_with(".done") => {
            out.push(Close::Tagged(tags(value)))
        }
        _ => {}
    }
    for (i, choice) in value
        .get("choices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        if choice.get("finish_reason").is_some_and(|r| !r.is_null()) {
            out.push(Close::Under(format!("/choices/{}/", element(choice, i))));
        }
    }
    out
}

/// Does this JSON text repeat a key in any object? A repeated key hides
/// the earlier value from a parsed view, so such data is scanned raw.
pub fn has_duplicate_keys(json: &str) -> bool {
    let mut found = Dups(false);
    let mut de = serde_json::Deserializer::from_str(json);
    (&mut found).deserialize(&mut de).is_ok() && found.0
}

struct Dups(bool);

impl<'de> DeserializeSeed<'de> for &mut Dups {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for &mut Dups {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(&mut *self)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                self.0 = true;
            }
            map.next_value_seed(&mut *self)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn duplicate_keys_are_found_at_any_depth() {
        assert!(!has_duplicate_keys(r#"{"a":1,"b":{"c":[1,{"d":2}]}}"#));
        assert!(has_duplicate_keys(r#"{"a":1,"a":2}"#));
        assert!(has_duplicate_keys(r#"{"x":[{"d":"s","d":"t"}]}"#));
    }

    #[test]
    fn closes_match_their_outputs() {
        let chat = json!({"choices":[{"index":1,"finish_reason":"stop","delta":{}}]});
        let close = closes(None, &chat);
        let lane = |path: &str| Lane {
            path: path.into(),
            tags: vec![],
        };
        assert!(close[0].covers(&lane("/choices/#1/delta/content")));
        assert!(!close[0].covers(&lane("/choices/#10/delta/content")));
        let stop = json!({"type":"content_block_stop","index":2});
        let close = closes(Some("content_block_stop"), &stop);
        let block = Lane {
            path: "/delta/text".into(),
            tags: vec![("i", 2)],
        };
        assert!(close[0].covers(&block));
        assert!(!close[0].covers(&Lane {
            tags: vec![("i", 3)],
            ..block
        }));
    }
}
