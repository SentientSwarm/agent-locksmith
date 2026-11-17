//! The text scanners see, and how a redaction is written back.
//!
//! A JSON body is scanned string by string (after JSON unescaping), so a
//! match is never hidden by escaping and a redaction rewrites only the
//! string it was found in. Every other byte of the body is kept as sent:
//! key order, number spelling (big integers included) and whitespace
//! (AGENT-270). Any other UTF-8 body is one segment.

use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Byte spans to redact in one segment, with the scanner that found them.
pub(super) type Spans = HashMap<usize, Vec<(usize, usize, String)>>;

pub(super) enum Document {
    /// Valid JSON text and its string tokens, keys included, in order.
    Json {
        text: String,
        tokens: Vec<Token>,
    },
    Text(String),
}

/// One JSON string token: its byte range (quotes included), whether it is
/// an object key, and which object it belongs to.
pub(super) struct Token {
    start: usize,
    end: usize,
    key: bool,
    object: usize,
}

pub(super) struct NotText;

impl Document {
    pub(super) fn parse(content_type: Option<&str>, body: &[u8]) -> Result<Self, NotText> {
        let text = std::str::from_utf8(body).map_err(|_| NotText)?;
        let json_type = content_type.is_some_and(|c| c.to_ascii_lowercase().contains("json"));
        if json_type && serde_json::from_str::<Value>(text).is_ok() {
            return Ok(Document::Json {
                tokens: string_tokens(text),
                text: text.to_string(),
            });
        }
        Ok(Document::Text(text.to_string()))
    }

    /// Every scannable string, in a fixed traversal order.
    pub(super) fn segments(&self) -> Vec<String> {
        match self {
            Document::Text(t) => vec![t.clone()],
            Document::Json { text, tokens } => tokens
                .iter()
                .map(|t| unescape_token(&text[t.start..t.end]))
                .collect(),
        }
    }

    /// Replace each span with `[REDACTED:<scanner>]`, rewriting only the
    /// string tokens that hold one.
    pub(super) fn redact(self, spans: &Spans) -> Vec<u8> {
        match self {
            Document::Text(t) => redact_str(&t, spans.get(&0).map(Vec::as_slice)).into_bytes(),
            Document::Json { text, tokens } => redact_tokens(&text, &tokens, spans).into_bytes(),
        }
    }
}

/// Every string token of valid JSON `text`, in document order. A `"`
/// outside a string can only open one, so a byte scan suffices.
fn string_tokens(text: &str) -> Vec<Token> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    // The enclosing container per depth: an object id, or None for arrays.
    let mut stack: Vec<Option<usize>> = Vec::new();
    let mut objects = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'{' => {
                stack.push(Some(objects));
                objects += 1;
            }
            b'[' => stack.push(None),
            b'}' | b']' => {
                stack.pop();
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                let end = (i + 1).min(b.len());
                let after = b[end..].iter().find(|c| !c.is_ascii_whitespace());
                let object = stack.last().copied().flatten();
                out.push(Token {
                    start,
                    end,
                    key: after == Some(&b':') && object.is_some(),
                    object: object.unwrap_or(usize::MAX),
                });
                i = end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

fn unescape_token(token: &str) -> String {
    serde_json::from_str(token).unwrap_or_default()
}

/// Copy `text`, replacing each token with spans by its redacted string.
/// A key redacted to a name already used in its object is numbered
/// (`#2`, `#3`, ...) so no value is lost. Every unredacted key of the
/// object is reserved first, so a redacted key never takes the name of
/// one that follows it, and a counter per name keeps numbering linear.
fn redact_tokens(text: &str, tokens: &[Token], spans: &Spans) -> String {
    let mut taken: HashMap<usize, HashSet<String>> = HashMap::new();
    for (index, t) in tokens.iter().enumerate() {
        if t.key && !spans.contains_key(&index) {
            taken
                .entry(t.object)
                .or_default()
                .insert(unescape_token(&text[t.start..t.end]));
        }
    }
    let mut next: HashMap<(usize, String), usize> = HashMap::new();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (index, t) in tokens.iter().enumerate() {
        let Some(found) = spans.get(&index) else {
            continue;
        };
        let mut value = redact_str(&unescape_token(&text[t.start..t.end]), Some(found));
        if t.key {
            let used = taken.entry(t.object).or_default();
            if used.contains(&value) {
                let n = next.entry((t.object, value.clone())).or_insert(2);
                let base = value.clone();
                loop {
                    value = format!("{base}#{n}");
                    *n += 1;
                    if !used.contains(&value) {
                        break;
                    }
                }
            }
            used.insert(value.clone());
        }
        out.push_str(&text[at..t.start]);
        out.push_str(&serde_json::to_string(&value).unwrap_or_default());
        at = t.end;
    }
    out.push_str(&text[at..]);
    out
}

/// How many further levels of JSON escaping the raw view is unescaped.
pub(super) const NESTED_ESCAPE_DEPTH: usize = 4;

/// Views of the raw bytes that catch what parsing hides: invalid UTF-8
/// (read lossily), escapes left in JSON that failed to parse, and form
/// encoding. The first view
/// is the JSON-unescaped body.
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

/// AGENT-270: JSON nested in a JSON string (tool arguments) keeps its
/// own escapes after one unescape. `view` unescaped again, up to
/// `NESTED_ESCAPE_DEPTH` more levels, stopping when nothing changes.
pub(super) fn nested_views(view: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for _ in 0..NESTED_ESCAPE_DEPTH {
        let last = out.last().map_or(view, String::as_str);
        let next = json_unescape(last);
        if next == last {
            break;
        }
        out.push(next);
    }
    out
}

/// Resolve JSON string escapes anywhere in `s`, leniently: a lone
/// surrogate becomes U+FFFD and an unknown escape is kept as written.
pub(super) fn json_unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let (chars, used) = unescape_step(rest);
        out.extend(chars.into_iter().flatten());
        rest = &rest[used..];
    }
    out
}

/// AGENT-315: [`nested_views`] of `text`, each with where its bytes come
/// from in `text`: `map[i]` is the offset of the text byte `i` was decoded
/// from, and `map[len]` is `text.len()`, so a span `a..b` of the view
/// came from `map[a]..map[b]`.
pub(super) fn nested_views_mapped(text: &str) -> Vec<(String, Vec<usize>)> {
    let mut out: Vec<(String, Vec<usize>)> = Vec::new();
    for _ in 0..NESTED_ESCAPE_DEPTH {
        let last = out.last().map_or(text, |(v, _)| v.as_str());
        if !last.contains('\\') {
            break;
        }
        let (next, map) = unescape_mapped(last);
        if next == last {
            break;
        }
        let map = match out.last() {
            Some((_, prev)) => map.into_iter().map(|i| prev[i]).collect(),
            None => map,
        };
        out.push((next, map));
    }
    out
}

fn unescape_mapped(s: &str) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(s.len());
    let mut map = Vec::with_capacity(s.len() + 1);
    let mut rest = s;
    while !rest.is_empty() {
        let at = s.len() - rest.len();
        let (chars, used) = unescape_step(rest);
        // An escape kept as written (`\q`) is two characters from two.
        for (i, c) in chars.into_iter().flatten().enumerate() {
            out.push(c);
            map.resize(out.len(), at + i);
        }
        rest = &rest[used..];
    }
    map.push(s.len());
    (out, map)
}

/// What [`json_unescape`] makes of the start of `rest` (one character, or
/// a backslash and the character it does not escape), and how many bytes
/// of `rest` that takes.
fn unescape_step(rest: &str) -> ([Option<char>; 2], usize) {
    let mut chars = rest.chars();
    let c = chars.next().expect("not empty");
    if c != '\\' {
        return ([Some(c), None], c.len_utf8());
    }
    let one = |c: char| ([Some(c), None], 2);
    match chars.next() {
        Some('n') => one('\n'),
        Some('t') => one('\t'),
        Some('r') => one('\r'),
        Some('b') => one('\u{8}'),
        Some('f') => one('\u{c}'),
        Some('u') => {
            let (c, used) = unicode_escape(&rest[2..]);
            ([Some(c), None], 2 + used)
        }
        Some(other @ ('"' | '\\' | '/')) => one(other),
        Some(other) => ([Some('\\'), Some(other)], 1 + other.len_utf8()),
        None => ([Some('\\'), None], 1),
    }
}

/// Up to four hex digits at the start of `s`: their value when there are
/// four, and how many there are.
fn hex4(s: &str) -> (Option<u32>, usize) {
    let n = s.bytes().take(4).take_while(u8::is_ascii_hexdigit).count();
    let value = (n == 4)
        .then(|| u32::from_str_radix(&s[..4], 16).ok())
        .flatten();
    (value, n)
}

/// The character a `\u` escape names, given the text after `\u`, and how
/// many bytes of it the escape takes (a surrogate pair takes its second
/// `\uXXXX` too). A short or lone-surrogate escape is U+FFFD.
fn unicode_escape(s: &str) -> (char, usize) {
    let (high, used) = hex4(s);
    let Some(high) = high else {
        return (char::REPLACEMENT_CHARACTER, used);
    };
    if (0xD800..0xDC00).contains(&high) {
        let low = s[used..]
            .strip_prefix("\\u")
            .and_then(|t| hex4(t).0)
            .filter(|l| (0xDC00..0xE000).contains(l));
        if let Some(low) = low {
            let code = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
            let c = char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER);
            return (c, used + 6);
        }
    }
    (
        char::from_u32(high).unwrap_or(char::REPLACEMENT_CHARACTER),
        used,
    )
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

    /// AGENT-315: every span of a nested view maps back to the escaped
    /// text it was decoded from, at any depth.
    #[test]
    fn nested_views_map_back_to_the_escaped_text() {
        // Two levels: `\\u0067` is `\u0067` once unescaped, then `g`.
        let text = r#"a \\u0067hp_x \\\"q \uD83D\uDE00 z"#;
        let views = nested_views_mapped(text);
        assert_eq!(views.len(), 2);
        let (view, map) = &views[1];
        assert_eq!(map.len(), view.len() + 1);
        let at = view.find("ghp_x").unwrap();
        assert_eq!(&text[map[at]..map[at + 5]], r"\\u0067hp_x");
        let at = view.find('q').unwrap();
        assert_eq!(&text[map[at]..map[at + 1]], "q");
        let smile = view.find('\u{1F600}').unwrap();
        assert_eq!(&text[map[smile]..map[smile + 4]], r"\uD83D\uDE00");
        assert_eq!(map[view.len()], text.len());
        let (view, map) = unescape_mapped(r"a\qb");
        assert_eq!(view, r"a\qb");
        assert_eq!(map, [0, 1, 2, 3, 4]);
    }

    #[test]
    fn unescaping_is_lenient() {
        for (text, want) in [
            (r"\u12g", "\u{FFFD}g"),
            (r"\uD83D x", "\u{FFFD} x"),
            (r"\q \", r"\q \"),
            (r"\n \t \/", "\n \t /"),
        ] {
            assert_eq!(json_unescape(text), want, "{text}");
            assert_eq!(unescape_mapped(text).0, want, "{text}");
        }
    }

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

    /// AGENT-270 — a redaction rewrites only the string it is in: key
    /// order, big integers, number spelling and whitespace are untouched.
    #[test]
    fn redaction_keeps_everything_else_byte_for_byte() {
        let body = concat!(
            "{\"z\": 1.50, \"big\": 123456789012345678901234567890,\n",
            " \"a\": [\"keep\", \"tok SECRET end\"], \"m\": -0}"
        );
        let doc = Document::parse(Some("application/json"), body.as_bytes())
            .ok()
            .unwrap();
        let segments = doc.segments();
        let at = segments.iter().position(|s| s == "tok SECRET end").unwrap();
        let mut spans: Spans = HashMap::new();
        spans.insert(at, vec![(4, 10, "s".to_string())]);
        let out = String::from_utf8(doc.redact(&spans)).unwrap();
        assert_eq!(out, body.replace("tok SECRET end", "tok [REDACTED:s] end"));
    }

    #[test]
    fn segments_follow_document_order_and_keep_duplicate_keys() {
        let doc = Document::parse(Some("application/json"), br#"{"b":"1","a":"2","b":"3"}"#)
            .ok()
            .unwrap();
        assert_eq!(doc.segments(), vec!["b", "1", "a", "2", "b", "3"]);
    }

    #[test]
    fn a_redacted_string_is_re_escaped() {
        let body = r#"{"k":"line\nSECRET \"q\" \u00e9"}"#;
        let doc = Document::parse(Some("application/json"), body.as_bytes())
            .ok()
            .unwrap();
        assert_eq!(doc.segments()[1], "line\nSECRET \"q\" \u{e9}");
        let mut spans: Spans = HashMap::new();
        spans.insert(1, vec![(5, 11, "s".to_string())]);
        let out: Value = serde_json::from_slice(&doc.redact(&spans)).unwrap();
        assert_eq!(out["k"], "line\n[REDACTED:s] \"q\" \u{e9}");
    }

    fn json(body: &str) -> Document {
        Document::parse(Some("application/json"), body.as_bytes())
            .ok()
            .unwrap()
    }

    #[test]
    fn a_redacted_key_never_takes_a_later_literal_key() {
        let doc = json(r#"{"SECRET":1,"[REDACTED:s]":2}"#);
        let mut spans: Spans = HashMap::new();
        spans.insert(0, vec![(0, 6, "s".to_string())]);
        let out: Value = serde_json::from_slice(&doc.redact(&spans)).unwrap();
        let obj = out.as_object().unwrap();
        assert_eq!(obj.len(), 2, "{out}");
        assert_eq!(obj["[REDACTED:s]"], 2, "the literal key keeps its value");
        assert_eq!(obj["[REDACTED:s]#2"], 1);
    }

    #[test]
    fn keys_in_different_objects_are_numbered_apart() {
        let doc = json(r#"{"o":{"S1":1},"p":{"S2":2}}"#);
        let mut spans: Spans = HashMap::new();
        // Segments: o, S1, p, S2.
        spans.insert(1, vec![(0, 2, "s".to_string())]);
        spans.insert(3, vec![(0, 2, "s".to_string())]);
        let out = String::from_utf8(doc.redact(&spans)).unwrap();
        assert_eq!(out, r#"{"o":{"[REDACTED:s]":1},"p":{"[REDACTED:s]":2}}"#);
    }

    #[test]
    fn many_keys_redacted_to_one_marker_number_in_linear_time() {
        let n = 30_000;
        let body = format!(
            "{{{}}}",
            (0..n)
                .map(|i| format!("\"k{i}\":0"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let doc = json(&body);
        let spans: Spans = (0..n)
            .map(|i| {
                let len = format!("k{i}").len();
                (i, vec![(0, len, "s".to_string())])
            })
            .collect();
        let started = std::time::Instant::now();
        let out: Value = serde_json::from_slice(&doc.redact(&spans)).unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(out.as_object().unwrap().len(), n);
    }

    /// The tokenizer's hard cases: a backslash before a closing quote,
    /// brackets and quotes inside strings, whitespace before `:`, a
    /// top-level string. With no spans the body comes back byte for
    /// byte, and the segments are exactly the parser's strings.
    #[test]
    fn tokenizer_finds_every_string_in_hard_json() {
        for body in [
            r#"{"a\\":"x\\","k" : "v","n":{"b{[":"]}\":"}}"#,
            r#"[ "s", {"x":["y", {"z" :"w"}]}, "t\"" ]"#,
            r#""top \u00e9 \"""#,
        ] {
            let doc = json(body);
            let mut segments = doc.segments();
            let mut expected = Vec::new();
            fn strings(v: &Value, out: &mut Vec<String>) {
                match v {
                    Value::String(s) => out.push(s.clone()),
                    Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
                    Value::Object(o) => o.iter().for_each(|(k, x)| {
                        out.push(k.clone());
                        strings(x, out)
                    }),
                    _ => {}
                }
            }
            strings(&serde_json::from_str(body).unwrap(), &mut expected);
            segments.sort();
            expected.sort();
            assert_eq!(segments, expected, "{body}");
            assert_eq!(
                json(body).redact(&HashMap::new()),
                body.as_bytes(),
                "{body}"
            );
        }
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
