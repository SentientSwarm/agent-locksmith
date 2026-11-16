//! AGENT-265 — server-sent events: parsing, text extraction, rewriting.
//!
//! Events are split on blank lines and kept as their raw bytes, so an
//! event nothing touches is forwarded byte for byte. Text is extracted
//! from the streaming shapes of the OpenAI chat and Responses APIs and
//! the Anthropic Messages API; anything else carries no text.

use super::lanes::{self, Close, Lane};
use serde_json::Value;

/// One event: its raw bytes (terminator included) and parsed fields.
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub raw: Vec<u8>,
    pub event: Option<String>,
    pub data: Option<String>,
}

/// A text field inside an event's JSON `data`, by JSON pointer, and the
/// output (lane) it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSpan {
    pub pointer: String,
    pub lane: Lane,
    pub text: String,
}

/// Which error shape a blocked stream ends with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    OpenAi,
    Anthropic,
}

/// Splits a byte stream into events (lines end in CRLF, LF or a lone CR;
/// a blank line ends an event). An event longer than `cap` bytes, complete
/// or not, is left unparsed and the parser reports `overflowed`. One
/// UTF-8 BOM at the start of the stream is ignored, as clients do.
pub struct SseParser {
    buf: Vec<u8>,
    /// Start of the first line not yet known to be complete.
    line_start: usize,
    cap: usize,
    overflowed: bool,
    /// No event has been emitted yet, so a leading BOM is the stream's.
    first: bool,
}

impl Default for SseParser {
    fn default() -> Self {
        Self::with_cap(usize::MAX)
    }
}

impl SseParser {
    pub fn with_cap(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            line_start: 0,
            cap,
            overflowed: false,
            first: true,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while !self.overflowed {
            let Some(end) = self.event_end() else {
                break;
            };
            if end > self.cap {
                self.overflowed = true;
                break;
            }
            let raw: Vec<u8> = self.buf.drain(..end).collect();
            self.line_start = 0;
            out.push(self.emit(raw));
        }
        if self.buf.len() > self.cap {
            self.overflowed = true;
        }
        out
    }

    fn emit(&mut self, raw: Vec<u8>) -> SseEvent {
        let bom = std::mem::take(&mut self.first) && raw.starts_with(BOM);
        parse_from(raw, if bom { BOM.len() } else { 0 })
    }

    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Whatever is buffered: an unterminated final event, or past an
    /// overflow the unparsed rest. Its `raw` is the bytes as received.
    pub fn finish(&mut self) -> Option<SseEvent> {
        self.line_start = 0;
        if self.buf.is_empty() {
            return None;
        }
        let raw = std::mem::take(&mut self.buf);
        Some(self.emit(raw))
    }

    /// End (exclusive) of the first complete event, resuming at the first
    /// line not yet seen complete.
    fn event_end(&mut self) -> Option<usize> {
        loop {
            let rel = self.buf[self.line_start..]
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')?;
            let at = self.line_start + rel;
            let term = match self.buf[at] {
                b'\n' => 1,
                // A CR at the end of the buffer may be half of a CRLF.
                _ if at + 1 == self.buf.len() => return None,
                _ if self.buf[at + 1] == b'\n' => 2,
                _ => 1,
            };
            let blank = at == self.line_start;
            self.line_start = at + term;
            if blank {
                return Some(self.line_start);
            }
        }
    }
}

const BOM: &[u8] = "\u{FEFF}".as_bytes();

/// An event from raw bytes (also an unterminated final one).
pub fn parse(raw: Vec<u8>) -> SseEvent {
    parse_from(raw, 0)
}

/// Parse `raw` from byte `skip` on, keeping all of `raw` to forward.
fn parse_from(raw: Vec<u8>, skip: usize) -> SseEvent {
    let text = String::from_utf8_lossy(&raw[skip..])
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut event = None;
    let mut data: Option<String> = None;
    for line in text.split('\n') {
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => event = Some(value.to_string()),
            "data" => match &mut data {
                Some(d) => {
                    d.push('\n');
                    d.push_str(value);
                }
                None => data = Some(value.to_string()),
            },
            _ => {}
        }
    }
    SseEvent { raw, event, data }
}

fn json(event: &SseEvent) -> Option<Value> {
    serde_json::from_str(event.data.as_deref()?).ok()
}

fn kind(event: &SseEvent, value: &Value) -> Option<String> {
    value
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| event.event.clone())
}

/// Metadata fields that carry no model text.
const METADATA: &[&str] = &[
    "type",
    "id",
    "object",
    "model",
    "role",
    "finish_reason",
    "stop_reason",
    "system_fingerprint",
    "status",
    "item_id",
    "call_id",
    "response_id",
    // Random padding (`stream_options.include_obfuscation`), the service
    // tier, and the agent's own instructions echoed back.
    "obfuscation",
    "service_tier",
    "instructions",
];

/// The text this event carries: every string in its JSON `data` except
/// metadata (delta and aggregate shapes alike), each in its output's
/// lane. Data that is not JSON, or JSON that repeats a key (whose earlier
/// value a parsed view would hide), is scanned whole (pointer `""`).
/// `[DONE]` and data-less events carry none.
pub fn extract(event: &SseEvent) -> Vec<TextSpan> {
    let Some(data) = event.data.as_deref() else {
        return Vec::new();
    };
    let parsed = serde_json::from_str::<Value>(data)
        .ok()
        .filter(|_| !lanes::has_duplicate_keys(data));
    let Some(value) = parsed else {
        let text = data.to_string();
        return if text.is_empty() || text == "[DONE]" {
            Vec::new()
        } else {
            vec![TextSpan {
                pointer: String::new(),
                lane: Lane {
                    path: String::new(),
                    tags: Vec::new(),
                },
                text,
            }]
        };
    };
    let tags = lanes::tags(&value);
    let mut out = Vec::new();
    leaves(&value, (String::new(), String::new()), &tags, &mut out);
    out
}

/// `at` is (JSON pointer, lane path).
fn leaves(
    value: &Value,
    at: (String, String),
    tags: &[(&'static str, i64)],
    out: &mut Vec<TextSpan>,
) {
    let (pointer, path) = at;
    match value {
        Value::String(text) => out.push(TextSpan {
            pointer,
            lane: Lane {
                path,
                tags: tags.to_vec(),
            },
            text: text.clone(),
        }),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let next = (
                    format!("{pointer}/{i}"),
                    format!("{path}/{}", lanes::element(item, i)),
                );
                leaves(item, next, tags, out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                if item.is_string() && METADATA.contains(&key.as_str()) {
                    continue;
                }
                let token = key.replace('~', "~0").replace('/', "~1");
                let next = (format!("{pointer}/{token}"), format!("{path}/{token}"));
                leaves(item, next, tags, out);
            }
        }
        _ => {}
    }
}

/// The lanes this event finishes (`[DONE]` finishes all).
pub fn closes(event: &SseEvent) -> Vec<Close> {
    if event.data.as_deref() == Some("[DONE]") {
        return vec![Close::All];
    }
    match json(event) {
        Some(value) => lanes::closes(kind(event, &value).as_deref(), &value),
        None => Vec::new(),
    }
}

/// The protocol an event belongs to, when it says.
pub fn protocol(event: &SseEvent) -> Option<Protocol> {
    let value = json(event)?;
    if value.get("choices").is_some() {
        return Some(Protocol::OpenAi);
    }
    let kind = kind(event, &value)?;
    if kind.starts_with("response.") {
        return Some(Protocol::OpenAi);
    }
    let anthropic =
        kind == "ping" || kind.starts_with("message_") || kind.starts_with("content_block_");
    anthropic.then_some(Protocol::Anthropic)
}

/// Re-serialise `event` with each pointer's text replaced (pointer `""`:
/// the whole non-JSON `data`).
pub fn rewrite(event: &SseEvent, edits: &[(String, String)]) -> Vec<u8> {
    // Pointer "" is data scanned whole (not JSON, or JSON with a repeated
    // key): it is rewritten as text.
    if let Some((_, text)) = edits.iter().find(|(p, _)| p.is_empty()) {
        return data_lines(event, text.split('\n').map(str::to_string).collect());
    }
    let Some(mut value) = json(event) else {
        return event.raw.clone();
    };
    for (pointer, text) in edits {
        if let Some(slot) = value.pointer_mut(pointer) {
            *slot = Value::String(text.clone());
        }
    }
    data_lines(event, vec![value.to_string()])
}

/// The event's non-data lines in order, with its data lines replaced.
fn data_lines(event: &SseEvent, data: Vec<String>) -> Vec<u8> {
    let bom = event.raw.starts_with(BOM);
    let raw = String::from_utf8_lossy(&event.raw[if bom { BOM.len() } else { 0 }..])
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut out = String::new();
    if bom {
        out.push('\u{FEFF}');
    }
    let mut data = Some(data);
    for line in raw.split('\n') {
        if line.starts_with("data:") {
            for d in data.take().unwrap_or_default() {
                out.push_str("data: ");
                out.push_str(&d);
                out.push('\n');
            }
        } else if !line.is_empty() {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push('\n');
    out.into_bytes()
}

/// The event that ends a blocked stream.
pub fn blocked_event(protocol: Protocol) -> Vec<u8> {
    let message = "response blocked by inspection";
    let data = match protocol {
        Protocol::OpenAi => serde_json::json!({
            "error": { "type": "inspection_error", "code": "inspection_blocked", "message": message }
        }),
        Protocol::Anthropic => serde_json::json!({
            "type": "error",
            "error": { "type": "inspection_blocked", "message": message }
        }),
    };
    format!("event: error\ndata: {data}\n\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(raw: &str) -> SseEvent {
        let mut p = SseParser::default();
        let mut events = p.push(raw.as_bytes());
        assert_eq!(events.len(), 1, "{raw:?}");
        events.remove(0)
    }

    #[test]
    fn splits_events_across_chunks() {
        let mut p = SseParser::default();
        assert!(p.push(b"data: {\"a\"").is_empty());
        let events = p.push(b":1}\n\ndata: [DONE]\r\n\r\nda");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].raw, b"data: {\"a\":1}\n\n");
        assert_eq!(events[1].data.as_deref(), Some("[DONE]"));
        assert_eq!(p.finish().map(|e| e.raw), Some(b"da".to_vec()));
    }

    #[test]
    fn extracts_each_protocol() {
        let chat = one(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\",\"tool_calls\":[{\"function\":{\"arguments\":\"{\\\"q\\\"\"}}]}}]}\n\n",
        );
        let texts: Vec<_> = extract(&chat).into_iter().map(|s| s.text).collect();
        assert_eq!(texts, vec!["hi", "{\"q\""]);
        let responses = one(
            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"yo\"}\n\n",
        );
        assert_eq!(extract(&responses)[0].text, "yo");
        let anthropic = one(
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hey\"}}\n\n",
        );
        assert_eq!(extract(&anthropic)[0].text, "hey");
        assert_eq!(protocol(&anthropic), Some(Protocol::Anthropic));
        assert_eq!(protocol(&chat), Some(Protocol::OpenAi));
    }

    #[test]
    fn non_text_events_carry_nothing() {
        for raw in [
            "event: ping\ndata: {\"type\":\"ping\"}\n\n",
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\"}}\n\n",
            "data: [DONE]\n\n",
            ": keep-alive comment\n\n",
        ] {
            assert!(extract(&one(raw)).is_empty(), "{raw:?}");
        }
    }

    #[test]
    fn rewrite_replaces_only_the_pointer() {
        let e = one(
            "event: x\nid: 7\ndata: {\"delta\":\"secret\",\"type\":\"response.output_text.delta\"}\n\n",
        );
        let out = String::from_utf8(rewrite(&e, &[("/delta".into(), "[R]".into())])).unwrap();
        assert!(out.starts_with("event: x\nid: 7\ndata: "), "{out}");
        assert!(out.ends_with("\n\n"));
        let again = one(&out);
        assert_eq!(extract(&again)[0].text, "[R]");
    }

    #[test]
    fn blocked_events_parse_as_their_protocol() {
        for p in [Protocol::OpenAi, Protocol::Anthropic] {
            let e = one(std::str::from_utf8(&blocked_event(p)).unwrap());
            assert_eq!(e.event.as_deref(), Some("error"));
            assert!(e.data.unwrap().contains("inspection_blocked"));
        }
    }

    #[test]
    fn lone_cr_line_endings_split_events() {
        let mut p = SseParser::default();
        let events = p.push(b"data: a\r\rdata: b\r\n\ndata: c\n\r\n");
        let data: Vec<_> = events.iter().map(|e| e.data.clone().unwrap()).collect();
        assert_eq!(data, vec!["a", "b", "c"]);
    }

    #[test]
    fn a_cr_at_the_end_of_a_chunk_waits_for_the_next() {
        let mut p = SseParser::default();
        assert!(p.push(b"data: a\r").is_empty());
        assert!(p.push(b"\n").is_empty());
        assert_eq!(p.push(b"\r\n").len(), 1);
    }

    #[test]
    fn every_content_string_is_extracted() {
        let done = one(
            "event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\",\"item_id\":\"it_1\",\"text\":\"full answer\"}\n\n",
        );
        assert_eq!(
            extract(&done)
                .into_iter()
                .map(|s| s.text)
                .collect::<Vec<_>>(),
            vec!["full answer"]
        );
        let start = one(
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"hello\"}}\n\n",
        );
        assert_eq!(extract(&start)[0].text, "hello");
        let plain = one("data: not json at all\n\n");
        assert_eq!(extract(&plain)[0].text, "not json at all");
        let out = String::from_utf8(rewrite(&plain, &[(String::new(), "x\ny".into())])).unwrap();
        assert_eq!(out, "data: x\ndata: y\n\n");
    }
}
