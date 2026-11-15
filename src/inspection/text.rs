//! The text scanners see, and how a redaction is written back.
//!
//! A JSON body is scanned string by string (after JSON unescaping), so a
//! match is never hidden by escaping and a redaction rewrites only the
//! string it was found in. Any other UTF-8 body is one segment.

use serde_json::Value;
use std::collections::HashMap;

/// Byte spans to redact in one segment, with the scanner that found them.
pub(super) type Spans = HashMap<usize, Vec<(usize, usize, String)>>;

pub(super) enum Document {
    Json(Value),
    Text(String),
}

pub(super) struct NotText;

impl Document {
    pub(super) fn parse(content_type: Option<&str>, body: &[u8]) -> Result<Self, NotText> {
        let text = std::str::from_utf8(body).map_err(|_| NotText)?;
        let json_type = content_type.is_some_and(|c| c.to_ascii_lowercase().contains("json"));
        if json_type && let Ok(value) = serde_json::from_str::<Value>(text) {
            return Ok(Document::Json(value));
        }
        Ok(Document::Text(text.to_string()))
    }

    /// Every scannable string, in a fixed traversal order.
    pub(super) fn segments(&self) -> Vec<String> {
        match self {
            Document::Text(t) => vec![t.clone()],
            Document::Json(v) => {
                let mut out = Vec::new();
                walk(v, &mut |s| out.push(s.to_string()));
                out
            }
        }
    }

    /// Replace each span with `[REDACTED:<scanner>]` and re-serialize.
    pub(super) fn redact(self, spans: &Spans) -> Vec<u8> {
        match self {
            Document::Text(t) => redact_str(&t, spans.get(&0).map(Vec::as_slice)).into_bytes(),
            Document::Json(mut v) => {
                let mut index = 0usize;
                walk_mut(&mut v, &mut |s| {
                    if let Some(found) = spans.get(&index) {
                        *s = redact_str(s, Some(found));
                    }
                    index += 1;
                });
                serde_json::to_vec(&v).unwrap_or_default()
            }
        }
    }
}

fn walk(v: &Value, f: &mut impl FnMut(&str)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(a) => a.iter().for_each(|x| walk(x, f)),
        Value::Object(o) => o.iter().for_each(|(k, x)| {
            f(k);
            walk(x, f)
        }),
        _ => {}
    }
}

fn walk_mut(v: &mut Value, f: &mut impl FnMut(&mut String)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| walk_mut(x, f)),
        Value::Object(o) => {
            // Keys are scanned too, so rebuild the map with redacted keys
            // in the same order `walk` visits them.
            let entries = std::mem::take(o);
            for (k, mut x) in entries {
                let mut key = k;
                f(&mut key);
                walk_mut(&mut x, f);
                o.insert(key, x);
            }
        }
        _ => {}
    }
}

/// Merge overlapping spans and replace them, last first.
fn redact_str(text: &str, spans: Option<&[(usize, usize, String)]>) -> String {
    let Some(spans) = spans else {
        return text.to_string();
    };
    let mut sorted: Vec<_> = spans.to_vec();
    sorted.sort_by_key(|s| s.0);
    let mut merged: Vec<(usize, usize, String)> = Vec::new();
    for (start, end, id) in sorted {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end, id)),
        }
    }
    let mut out = text.to_string();
    for (start, end, id) in merged.into_iter().rev() {
        if out.is_char_boundary(start) && out.is_char_boundary(end) && end <= out.len() {
            out.replace_range(start..end, &format!("[REDACTED:{id}]"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_strings_are_scanned_unescaped() {
        let doc = Document::parse(Some("application/json"), br#"{"a":"xAy","b":[1,"z"]}"#)
            .ok()
            .unwrap();
        assert_eq!(
            doc.segments(),
            vec![
                "a".to_string(),
                "xAy".to_string(),
                "b".to_string(),
                "z".to_string()
            ]
        );
    }

    #[test]
    fn overlapping_spans_merge() {
        let spans = vec![(0, 3, "s".to_string()), (2, 5, "s".to_string())];
        assert_eq!(redact_str("abcdefg", Some(&spans)), "[REDACTED:s]fg");
    }
}
