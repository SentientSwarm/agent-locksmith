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
use std::collections::HashMap;
use std::fmt;

/// One output of a stream: the field's path, with each array position
/// that carries an integer `index` replaced by `#<index>`, and the
/// event's top-level indexes as tags.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Lane {
    pub path: String,
    pub tags: Vec<(&'static str, i64)>,
}

/// Top-level fields that name which output an event belongs to.
const TAGS: [(&str, &str); 4] = [
    ("index", "i"),
    ("output_index", "o"),
    ("content_index", "c"),
    ("summary_index", "s"),
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

/// A protocol that names its outputs with top-level indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// OpenAI Responses: `output_index`, `content_index`, `summary_index`.
    Responses,
    /// Anthropic Messages: a content block's `index`.
    Anthropic,
}

/// The scheme an event type belongs to.
pub fn scheme_of(kind: &str) -> Option<Scheme> {
    if kind.starts_with("response.") {
        Some(Scheme::Responses)
    } else if kind == "ping" || kind.starts_with("message_") || kind.starts_with("content_block_") {
        Some(Scheme::Anthropic)
    } else {
        None
    }
}

/// The tags an event's top-level indexes give, counting only the indexes
/// the stream's protocol (`scheme`, fixed per stream) uses to name the
/// output of an event of type `kind`, as its clients rebuild it: Responses
/// content parts by output and content index, reasoning summaries by
/// output and summary index, anything else by output index; Anthropic
/// blocks by `index`. Other protocols name none (a chat choice is named
/// inside `choices`), so an upstream can't split one output across
/// windows by adding or varying indexes its clients ignore.
pub fn tags(scheme: Option<Scheme>, kind: Option<&str>, value: &Value) -> Vec<(&'static str, i64)> {
    let kind = kind.unwrap_or("");
    let fields: &[&str] = match scheme {
        Some(Scheme::Responses) if kind.contains("reasoning_summary") => {
            &["output_index", "summary_index"]
        }
        Some(Scheme::Responses)
            if ["output_text", "refusal", "reasoning_text", "content_part"]
                .iter()
                .any(|part| kind.contains(part)) =>
        {
            &["output_index", "content_index"]
        }
        Some(Scheme::Responses) => &["output_index"],
        Some(Scheme::Anthropic) => &["index"],
        None => &[],
    };
    TAGS.iter()
        .filter(|(field, _)| fields.contains(field))
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

/// For a chat tool call's lane, the path prefix of its choice's calls
/// and the call's index (`/choices/#0/delta/tool_calls/` and `3` for
/// `/choices/#0/delta/tool_calls/#3/function/arguments`).
pub fn tool_call(path: &str) -> Option<(&str, i64)> {
    const CALLS: &str = "/delta/tool_calls/#";
    if !path.starts_with("/choices/") {
        return None;
    }
    let at = path.find(CALLS)? + CALLS.len();
    let (n, _) = path[at..].split_once('/')?;
    Some((&path[..at - 1], n.parse().ok()?))
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
    /// A chat choice's tool calls (lanes under `calls`, then `#<n>/`)
    /// numbered below `index`: a chat stream sends its calls one after
    /// another, so a later call starting finishes the earlier ones
    /// (AGENT-273). An upstream that interleaves calls then writes to a
    /// finished output, which `fail_closed` blocks.
    Earlier { calls: String, index: i64 },
}

impl Close {
    pub fn covers(&self, lane: &Lane) -> bool {
        match self {
            Close::All => true,
            Close::Under(prefix) => lane.path.starts_with(prefix),
            Close::Tagged(tags) => !tags.is_empty() && tags.iter().all(|t| lane.tags.contains(t)),
            Close::Earlier { calls, index } => lane
                .path
                .strip_prefix(calls.as_str())
                .and_then(|rest| rest.strip_prefix('#')?.split_once('/'))
                .and_then(|(n, _)| n.parse::<i64>().ok())
                .is_some_and(|n| n < *index),
        }
    }
}

/// The lanes `value` (an event's `data`, of type `kind`) finishes.
pub fn closes(kind: Option<&str>, scheme: Option<Scheme>, value: &Value) -> Vec<Close> {
    let mut out = Vec::new();
    match kind {
        Some("message_stop" | "response.completed" | "response.failed" | "response.incomplete") => {
            out.push(Close::All)
        }
        Some("content_block_stop") => out.push(Close::Tagged(tags(scheme, kind, value))),
        Some(k) if k.starts_with("response.") && k.ends_with(".done") => {
            out.push(Close::Tagged(tags(scheme, kind, value)))
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
        let at = element(choice, i);
        let latest = choice
            .pointer("/delta/tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|call| call.get("index").and_then(index))
            .max();
        if let Some(latest) = latest {
            out.push(Close::Earlier {
                calls: format!("/choices/{at}/delta/tool_calls/"),
                index: latest,
            });
        }
        if choice.get("finish_reason").is_some_and(|r| !r.is_null()) {
            out.push(Close::Under(format!("/choices/{at}/")));
        }
    }
    out
}

/// The strings a repeated key hides from a parsed view: everything
/// inside each value but the last for that key, at any depth. A client
/// whose parser keeps the first value reads them, so they are scanned too.
/// `None` when no key repeats.
pub fn hidden_strings(json: &str) -> Option<Vec<String>> {
    let mut hidden = Hidden(Vec::new(), false);
    let mut de = serde_json::Deserializer::from_str(json);
    (&mut hidden).deserialize(&mut de).ok()?;
    hidden.1.then_some(hidden.0)
}

/// Collects hidden strings (and whether any key repeated); each value
/// visited yields the strings in it.
struct Hidden(Vec<String>, bool);

impl<'de> DeserializeSeed<'de> for &mut Hidden {
    type Value = Vec<String>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Vec<String>, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for &mut Hidden {
    type Value = Vec<String>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Vec<String>, E> {
        Ok(Vec::new())
    }
    fn visit_i64<E>(self, _: i64) -> Result<Vec<String>, E> {
        Ok(Vec::new())
    }
    fn visit_u64<E>(self, _: u64) -> Result<Vec<String>, E> {
        Ok(Vec::new())
    }
    fn visit_f64<E>(self, _: f64) -> Result<Vec<String>, E> {
        Ok(Vec::new())
    }
    fn visit_str<E>(self, s: &str) -> Result<Vec<String>, E> {
        Ok(vec![s.to_string()])
    }
    fn visit_unit<E>(self) -> Result<Vec<String>, E> {
        Ok(Vec::new())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
        let mut all = Vec::new();
        while let Some(inner) = seq.next_element_seed(&mut *self)? {
            all.extend(inner);
        }
        Ok(all)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Vec<String>, A::Error> {
        let mut by_key: HashMap<String, Vec<Vec<String>>> = HashMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let mut inner = map.next_value_seed(&mut *self)?;
            // A key is text too: one inside a hidden value is hidden.
            inner.push(key.clone());
            by_key.entry(key).or_default().push(inner);
        }
        let mut all = Vec::new();
        for mut values in by_key.into_values() {
            let last = values.pop().unwrap_or_default();
            for hidden in values {
                self.1 = true;
                self.0.extend(hidden);
            }
            all.extend(last);
        }
        Ok(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_tool_call_lane_names_its_choice_and_index() {
        let call = "/choices/#0/delta/tool_calls/#3/function/arguments";
        assert_eq!(tool_call(call), Some(("/choices/#0/delta/tool_calls/", 3)));
        let negative = "/choices/#1/delta/tool_calls/#-1/function/name";
        assert_eq!(
            tool_call(negative),
            Some(("/choices/#1/delta/tool_calls/", -1))
        );
        assert_eq!(tool_call("/choices/#0/delta/content"), None);
        assert_eq!(
            tool_call("/choices/#0/delta/tool_calls/2/function/name"),
            None
        );
        assert_eq!(
            tool_call("/choices/#0/delta/tool_calls/#x/function/name"),
            None
        );
        assert_eq!(tool_call("/delta/tool_calls/#1/function/name"), None);
    }

    /// AGENT-273: a tool call starting finishes the lower-numbered calls
    /// of its own choice, compared as numbers, and nothing else.
    #[test]
    fn a_later_tool_call_finishes_the_earlier_ones_in_its_choice() {
        let v = json!({"choices": [{"index": 1, "delta": {"tool_calls": [
            {"index": 3, "function": {"arguments": "x"}},
            {"index": 10, "function": {"arguments": "y"}}]}}]});
        let c = closes(None, None, &v);
        assert_eq!(c.len(), 1, "{c:?}");
        let covers = |path: &str| {
            c[0].covers(&Lane {
                path: path.into(),
                tags: vec![],
            })
        };
        assert!(covers("/choices/#1/delta/tool_calls/#2/function/arguments"));
        assert!(covers("/choices/#1/delta/tool_calls/#9/function/name"));
        assert!(!covers(
            "/choices/#1/delta/tool_calls/#10/function/arguments"
        ));
        assert!(!covers("/choices/#1/delta/tool_calls/#11/function/name"));
        assert!(!covers(
            "/choices/#0/delta/tool_calls/#2/function/arguments"
        ));
        assert!(!covers("/choices/#1/delta/content"));
        assert!(!covers("/choices/#1/delta/tool_calls/2/function/arguments"));
    }

    #[test]
    fn hidden_strings_are_found_at_any_depth() {
        let has = |j: &str, want: &[&str]| {
            let got = hidden_strings(j).unwrap_or_else(|| panic!("no repeat in {j}"));
            for w in want {
                assert!(got.contains(&w.to_string()), "{w} not in {got:?} for {j}");
            }
        };
        assert_eq!(
            hidden_strings(r#"{"a":"x","b":{"c":["y",{"d":"z"}]}}"#),
            None
        );
        has(r#"{"a":"one","a":"two"}"#, &["one"]);
        has(r#"{"x":[{"d":"s","d":"t"}]}"#, &["s"]);
        has(r#"{"a":{"b":"in"},"a":"out"}"#, &["in", "b"]);
        has(r#"{"a":"\u0067h","a":"x"}"#, &["gh"]);
        has(r#"{"n":1,"n":2}"#, &[]);
        has(r#"{"x":{"sec":1},"x":null}"#, &["sec"]);
        let two = hidden_strings(r#"{"a":"one","a":"two"}"#).unwrap();
        assert!(
            !two.contains(&"two".to_string()),
            "the kept value is not hidden"
        );
    }

    #[test]
    fn closes_match_their_outputs() {
        let chat = json!({"choices":[{"index":1,"finish_reason":"stop","delta":{}}]});
        let close = closes(None, None, &chat);
        let lane = |path: &str| Lane {
            path: path.into(),
            tags: vec![],
        };
        assert!(close[0].covers(&lane("/choices/#1/delta/content")));
        assert!(!close[0].covers(&lane("/choices/#10/delta/content")));
        let stop = json!({"type":"content_block_stop","index":2});
        let close = closes(Some("content_block_stop"), Some(Scheme::Anthropic), &stop);
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
