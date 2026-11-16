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

/// Views of the raw bytes that catch what parsing hides: invalid UTF-8
/// (read lossily), escapes left in JSON that failed to parse, values of
/// duplicate keys the parser dropped, and form encoding.
pub(super) fn raw_views(content_type: Option<&str>, body: &[u8]) -> Vec<String> {
    let lossy = String::from_utf8_lossy(body);
    let mut views = vec![json_unescape(&lossy)];
    let form = content_type.is_some_and(|c| {
        c.to_ascii_lowercase()
            .contains("application/x-www-form-urlencoded")
    });
    if form {
        views.push(percent_decode(&lossy));
    }
    views
}

/// Resolve JSON string escapes anywhere in `s`, leniently: a lone
/// surrogate becomes U+FFFD and an unknown escape is kept as written.
pub(super) fn json_unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('u') => out.push(unicode_escape(&mut chars)),
            Some(other @ ('"' | '\\' | '/')) => out.push(other),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn hex4(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<u32> {
    let digits: String = (0..4)
        .map_while(|_| chars.next_if(char::is_ascii_hexdigit))
        .collect();
    (digits.len() == 4).then(|| u32::from_str_radix(&digits, 16).ok())?
}

fn unicode_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> char {
    let Some(high) = hex4(chars) else {
        return char::REPLACEMENT_CHARACTER;
    };
    if (0xD800..0xDC00).contains(&high) {
        let mut ahead = chars.clone();
        let low = (ahead.next() == Some('\\') && ahead.next() == Some('u'))
            .then(|| hex4(&mut ahead))
            .flatten()
            .filter(|l| (0xDC00..0xE000).contains(l));
        if let Some(low) = low {
            *chars = ahead;
            let code = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
            return char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER);
        }
    }
    char::from_u32(high).unwrap_or(char::REPLACEMENT_CHARACTER)
}

/// Percent-decode a query or form (`+` is a space), reading lossily.
pub(crate) fn percent_decode(s: &str) -> String {
    decode(s, true)
}

/// Percent-decode a URL path, where `+` is a literal plus.
pub(crate) fn percent_decode_path(s: &str) -> String {
    decode(s, false)
}

/// Every decoding of a URL path that some hop may apply: axum decodes the
/// path once before Locksmith builds the upstream URL, and the upstream
/// decodes again, so `%2543` reaches the upstream as `C` (AGENT-270).
/// Decodes until nothing changes, at most [`PATH_DECODE_ROUNDS`] times.
pub(crate) fn path_views(raw: &str) -> Vec<String> {
    let mut views = vec![percent_decode_path(raw)];
    while views.len() < PATH_DECODE_ROUNDS {
        let next = percent_decode_path(views.last().expect("one view"));
        if &next == views.last().expect("one view") {
            break;
        }
        views.push(next);
    }
    views
}

/// Bounds [`path_views`]; each round shrinks a path that changes.
const PATH_DECODE_ROUNDS: usize = 4;

fn decode(s: &str, plus_is_space: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match bytes[i] {
            b'+' if plus_is_space => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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
                // Two keys redacted to the same marker must not overwrite
                // each other: number the later ones.
                if o.contains_key(&key) {
                    let base = key.clone();
                    let mut n = 2;
                    while o.contains_key(&key) {
                        key = format!("{base}#{n}");
                        n += 1;
                    }
                }
                o.insert(key, x);
            }
        }
        _ => {}
    }
}

/// Merge overlapping spans and replace each with its marker.
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
    // One pass: copy between spans, a marker for each.
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (start, end, id) in merged {
        let valid = start >= at
            && end <= text.len()
            && text.is_char_boundary(start)
            && text.is_char_boundary(end);
        if !valid {
            continue;
        }
        out.push_str(&text[at..start]);
        out.push_str(&format!("[REDACTED:{id}]"));
        at = end;
    }
    out.push_str(&text[at..]);
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

    #[test]
    fn colliding_redacted_keys_keep_both_values() {
        let doc = Document::parse(Some("application/json"), br#"{"k1":1,"k2":2}"#)
            .ok()
            .unwrap();
        let mut spans: Spans = HashMap::new();
        spans.insert(0, vec![(0, 2, "s".to_string())]);
        spans.insert(1, vec![(0, 2, "s".to_string())]);
        let out: Value = serde_json::from_slice(&doc.redact(&spans)).unwrap();
        let obj = out.as_object().unwrap();
        assert_eq!(obj.len(), 2, "{out}");
        let mut values: Vec<_> = obj.values().cloned().collect();
        values.sort_by_key(|v| v.as_i64());
        assert_eq!(values, vec![Value::from(1), Value::from(2)]);
        assert!(obj.keys().all(|k| k.starts_with("[REDACTED:s]")));
    }

    #[test]
    fn path_views_follow_every_decoding_hop() {
        assert_eq!(path_views("/a/b"), vec!["/a/b"]);
        assert_eq!(path_views("/x%2543"), vec!["/x%43", "/xC"]);
        assert_eq!(
            path_views("/x%25252543"),
            vec!["/x%252543", "/x%2543", "/x%43", "/xC"]
        );
        assert_eq!(path_views("/x%2525252543").len(), 4);
    }

    #[test]
    fn path_decoding_keeps_a_literal_plus() {
        assert_eq!(percent_decode_path("a+b%2Bc%20d"), "a+b+c d");
        assert_eq!(percent_decode("a+b%2Bc"), "a b+c");
    }

    #[test]
    fn many_spans_redact_in_one_pass() {
        let text = "ab".repeat(200_000);
        let spans: Vec<_> = (0..200_000)
            .map(|i| (i * 2, i * 2 + 1, "s".to_string()))
            .collect();
        let started = std::time::Instant::now();
        let out = redact_str(&text, Some(&spans));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(out, "[REDACTED:s]b".repeat(200_000));
    }
}
