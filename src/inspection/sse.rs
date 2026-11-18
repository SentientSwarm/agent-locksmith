//! AGENT-265 — server-sent events: parsing, text extraction, rewriting.
//!
//! Events are split on blank lines and kept as their raw bytes, so an
//! event nothing touches is forwarded byte for byte. Text is extracted
//! from the streaming shapes of the OpenAI chat and Responses APIs and
//! the Anthropic Messages API; in any other JSON every string is a field
//! (its lane named by its path). Object keys are fields too.
//!
//! A field later events extend (a delta) belongs to a lane; a field
//! complete in its own event (a snapshot: `response.created`, any
//! Responses event but a `*.delta`, Anthropic message events, a chat
//! chunk's fields outside `delta`, protocol metadata, keys) has none and
//! is scanned alone.

use super::lanes::{self, Close, Lane};
use serde_json::Value;
use std::collections::HashMap;

/// One event: its raw bytes (terminator included) and parsed fields.
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub raw: Vec<u8>,
    pub event: Option<String>,
    pub data: Option<String>,
}

/// Where a text field lives in its event, for rewriting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// The whole `data`, which is not JSON: rewritten as text.
    Raw,
    /// A string in the JSON `data`, by pointer (`""`: a root string).
    Json(String),
    /// A value a repeated key hides: a rewrite re-serialises the parsed
    /// view, which drops it.
    Hidden,
    /// An object key (in the object at pointer `parent`): rewritten by
    /// renaming it.
    Key { parent: String, key: String },
    /// Decoded text no rewrite can reach (data that does not parse, with
    /// its escapes resolved): a redact of it blocks. `json`: the data is
    /// shaped like JSON, so a client may decode it, and it can't be
    /// judged as text (`fail_closed` blocks).
    View { json: bool },
}

/// A text field of an event, and the output (lane) later events extend
/// it in; `None` when it is complete in this event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSpan {
    pub place: Place,
    pub lane: Option<Lane>,
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
    /// Bytes already searched for a line end, so a long line arriving in
    /// small chunks is searched once.
    searched: usize,
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
            searched: 0,
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
            self.searched = 0;
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
        self.searched = 0;
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
            let from = self.line_start.max(self.searched);
            let Some(rel) = self.buf[from..]
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
            else {
                self.searched = self.buf.len();
                return None;
            };
            let at = from + rel;
            let term = match self.buf[at] {
                b'\n' => 1,
                // A CR at the end of the buffer may be half of a CRLF.
                _ if at + 1 == self.buf.len() => {
                    self.searched = at;
                    return None;
                }
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

/// See [`lanes::indexes_are_plain`]; data that is not JSON names none.
pub fn indexes_are_plain(event: &SseEvent, scheme: Option<lanes::Scheme>) -> bool {
    json(event).is_none_or(|v| lanes::indexes_are_plain(scheme, kind(event, &v).as_deref(), &v))
}

/// A Gemini chunk's text parts in order, as (candidate position, is a
/// thought), or `None` when clients read the chunk in different ways
/// (AGENT-322): a `candidates` or `parts` that is not an array, a
/// candidate whose `index` is not its position (clients read either) or
/// that has none past position 0, or
/// a `thought` that is not a boolean (the JavaScript SDK takes only `true`
/// as a thought, Python reads `"false"` or `"0"` by its words, a raw
/// reader by truthiness). An event without `candidates`, and data that
/// is not JSON, name none.
pub fn gemini_parts(event: &SseEvent) -> Option<Vec<(usize, bool)>> {
    let Some(value) = json(event) else {
        return Some(Vec::new());
    };
    let Some(candidates) = value.get("candidates").filter(|c| !c.is_null()) else {
        return Some(Vec::new());
    };
    let mut parts = Vec::new();
    for (at, c) in candidates.as_array()?.iter().enumerate() {
        // A client keying candidates by `index` may read a missing one as
        // 0, so past position 0 one must name its own.
        if c.get("index")
            .map_or(at > 0, |i| i.as_u64() != Some(at as u64))
        {
            return None;
        }
        let Some(list) = c.pointer("/content/parts") else {
            continue;
        };
        for part in list.as_array()? {
            let thought = match part.get("thought") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return None,
            };
            if part
                .get("text")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            {
                parts.push((at, thought));
            }
        }
    }
    Some(parts)
}

/// Whether the event is JSON-RPC 2.0 (a message or a batch of them), or
/// `None` when its data is not JSON. A stream's first JSON event fixes
/// whether the stream is JSON-RPC, as its first protocol event fixes its
/// scheme, so a `jsonrpc` field added mid-stream scans nothing whole.
pub fn is_jsonrpc(event: &SseEvent) -> Option<bool> {
    let value = json(event)?;
    let message = |v: &Value| v.get("jsonrpc").and_then(Value::as_str) == Some("2.0");
    Some(match &value {
        Value::Array(batch) => !batch.is_empty() && batch.iter().all(message),
        other => message(other),
    })
}

/// The members a JSON-RPC 2.0 message may have.
const JSONRPC_MEMBERS: [&str; 6] = ["jsonrpc", "id", "method", "params", "result", "error"];

/// The members that name an MCP result: a list (`tools/list` and the
/// rest), a read, a tool call's output or a prompt.
const MCP_RESULTS: [&str; 8] = [
    "tools",
    "resources",
    "resourceTemplates",
    "prompts",
    "contents",
    "content",
    "structuredContent",
    "messages",
];

/// An MCP result: a JSON-RPC 2.0 message with only the spec's members
/// whose `result` names an MCP result. MCP sends each result whole, and
/// no MCP client joins one message's strings with another's. Any other
/// JSON-RPC message keeps its windows, since other protocols (A2A, ACP)
/// stream text across messages that their clients join.
fn mcp_result(value: &Value, kind: Option<&str>) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let names_mcp = object
        .get("result")
        .and_then(Value::as_object)
        .is_some_and(|result| result.keys().any(|k| MCP_RESULTS.contains(&k.as_str())));
    object.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && object.keys().all(|k| JSONRPC_MEMBERS.contains(&k.as_str()))
        && names_mcp
        && kind.and_then(lanes::scheme_of).is_none()
}

/// Whether a string's path lies under an MCP result's member
/// (`/result/tools/...`). Only those are scanned whole: any other field
/// of the message keeps its window, whatever MCP member sits beside it.
fn under_mcp_member(path: &str) -> bool {
    path.strip_prefix("/result/")
        .map(|rest| rest.split('/').next().unwrap_or(rest))
        .is_some_and(|member| MCP_RESULTS.contains(&member))
}

fn json(event: &SseEvent) -> Option<Value> {
    serde_json::from_str(event.data.as_deref()?).ok()
}

/// The event's protocol scheme, from its `type` or its event name.
pub fn scheme(event: &SseEvent) -> Option<lanes::Scheme> {
    let value = json(event)?;
    lanes::scheme_of(&kind(event, &value)?)
}

/// The event's name and its data's `type` differ and at least one names a
/// protocol event: a client dispatching on one reads it differently from
/// one dispatching on the other. The SSE default name `message` names no
/// event type.
pub fn names_disagree(event: &SseEvent) -> bool {
    let Some(name) = event.event.as_deref().filter(|n| *n != "message") else {
        return false;
    };
    let Some(value) = json(event) else {
        return false;
    };
    let Some(kind) = value.get("type").and_then(Value::as_str) else {
        return false;
    };
    kind != name && (lanes::scheme_of(kind).is_some() || lanes::scheme_of(name).is_some())
}

/// The event is a snapshot clients append later deltas to (Responses
/// `response.created` / `in_progress` output, an `output_item.added`
/// item's content or summary, Anthropic `message_start` content) and it
/// already carries text there. Real streams open these empty; text in one
/// is scanned alone, so a match split from it into the deltas is missed.
pub fn seeds_output(event: &SseEvent) -> bool {
    let Some(value) = json(event) else {
        return false;
    };
    let roots: &[&str] = match kind(event, &value).as_deref() {
        Some("response.created" | "response.in_progress") => &["/response/output"],
        Some("response.output_item.added") => &["/item/content", "/item/summary"],
        Some("message_start") => &["/message/content"],
        _ => return false,
    };
    roots
        .iter()
        .filter_map(|root| value.pointer(root))
        .any(has_text)
}

/// Any non-empty string anywhere in `value`.
fn has_text(value: &Value) -> bool {
    match value {
        Value::String(s) => !s.is_empty(),
        Value::Array(items) => items.iter().any(has_text),
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| !METADATA.contains(&k.as_str()) && has_text(v)),
        _ => false,
    }
}

fn kind(event: &SseEvent, value: &Value) -> Option<String> {
    value
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| event.event.clone())
}

/// Protocol metadata names. They are scanned like any string, but are
/// complete in each event, so they never join a lane.
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

/// The text this event carries: every non-empty string and object key in
/// its JSON `data` (delta and aggregate shapes alike), each string with
/// its lane, plus any value a repeated key hides. Data that is not JSON is
/// one field, plus its decoded view when it looks like JSON. `[DONE]` and
/// data-less events carry none.
pub fn extract(event: &SseEvent) -> Vec<TextSpan> {
    extract_within(event, usize::MAX, scheme(event), false).unwrap_or_default()
}

/// [`extract`], or `None` when the fields' text and locations together
/// pass `limit` bytes (deep paths can outweigh the event many times).
/// `scheme` is the stream's protocol, which names outputs' lane tags;
/// `jsonrpc_stream`, whether the stream's first JSON event was a JSON-RPC
/// message (see [`is_jsonrpc`]).
pub fn extract_within(
    event: &SseEvent,
    limit: usize,
    scheme: Option<lanes::Scheme>,
    jsonrpc_stream: bool,
) -> Option<Vec<TextSpan>> {
    let Some(data) = event.data.as_deref() else {
        return Some(Vec::new());
    };
    let Ok(value) = serde_json::from_str::<Value>(data) else {
        if data.is_empty() || data == "[DONE]" {
            return Some(Vec::new());
        }
        let mut out = vec![TextSpan {
            place: Place::Raw,
            lane: Some(Lane::default()),
            text: data.to_string(),
        }];
        // JSON the parser refuses (a number out of range, nesting too
        // deep, a string left open) that a client may still decode, with
        // or without escapes, or text with escapes: its escapes hide
        // nothing, and JSON-shaped data can't be judged as text.
        let json = data.trim_start().starts_with(['{', '[', '"']);
        if json || data.contains('\\') {
            out.push(TextSpan {
                place: Place::View { json },
                lane: None,
                text: super::text::json_unescape(data),
            });
        }
        return Some(out);
    };
    let kind = kind(event, &value);
    let chat = value.get("choices").is_some_and(Value::is_array)
        && kind.as_deref().and_then(lanes::scheme_of).is_none();
    // A Gemini chunk. A `choices` array or a protocol `type` beside
    // `candidates` (no real event has both) changes nothing for the
    // candidates a Gemini client reads (AGENT-322).
    let gemini = value.get("candidates").is_some_and(Value::is_array);
    // An MCP result (MCP over SSE) is complete in its event: no client
    // joins one message's strings with another's, so in a JSON-RPC stream
    // the strings under its MCP member are scanned whole instead of taking
    // a window each (AGENT-273).
    let mcp_whole = jsonrpc_stream && mcp_result(&value, kind.as_deref());
    let tags = lanes::tags(scheme, kind.as_deref(), &value);
    let mut walk = Walk {
        limit,
        ..Walk::default()
    };
    walk.value(&value);
    if walk.over {
        return None;
    }
    let mut out: Vec<TextSpan> = walk
        .found
        .into_iter()
        .map(|(place, path, text)| {
            let lane =
                path.filter(|path| !(mcp_whole && under_mcp_member(path)))
                    .and_then(|path| match (gemini, &place) {
                        (true, _) if gemini_whole(&path) => None,
                        (true, Place::Json(pointer)) => gemini_text(pointer)
                            .or_else(|| stream_path(kind.as_deref(), chat, &path)),
                        _ => stream_path(kind.as_deref(), chat, &path),
                    })
                    .map(|path| Lane {
                        // A choice is named by its `#index` in the path, a
                        // Gemini candidate by its position (AGENT-322).
                        tags: if path.starts_with("/choices/")
                            || (gemini && path.starts_with("/candidates/"))
                        {
                            Vec::new()
                        } else {
                            tags.clone()
                        },
                        path,
                    });
            TextSpan { place, lane, text }
        })
        .collect();
    if let Some(hidden) = lanes::hidden_strings(data) {
        // At least one hidden span, even empty, so the repeat is visible.
        let mut texts: Vec<String> = hidden.into_iter().filter(|t| !t.is_empty()).collect();
        if texts.is_empty() {
            texts.push(String::new());
        }
        out.extend(texts.into_iter().map(|text| TextSpan {
            place: Place::Hidden,
            lane: None,
            text,
        }));
    }
    Some(out)
}

/// A Gemini `generateContent` chunk's metadata, whole in each chunk and
/// never joined across chunks by a client: the model version, the
/// response id, the usage counts, a candidate's role and finish reason,
/// and a part's opaque thought signature. Matched by exact place, not by
/// name, so a field of the same name elsewhere keeps its lane. In a lane,
/// a field repeated in every chunk but shorter than the text (`role`, a
/// usage `modality`), or one sent once and never extended (a signature),
/// would hold the stream until its own lane passed the overlap
/// (AGENT-273).
fn gemini_whole(path: &str) -> bool {
    if matches!(path, "/modelVersion" | "/responseId") || path.starts_with("/usageMetadata/") {
        return true;
    }
    let Some(rest) = path.strip_prefix("/candidates/") else {
        return false;
    };
    let Some((_, field)) = rest.split_once('/') else {
        return false;
    };
    if matches!(field, "content/role" | "finishReason") {
        return true;
    }
    // `content/parts/<part>/thoughtSignature`
    field
        .strip_prefix("content/parts/")
        .and_then(|part| part.split_once('/'))
        .is_some_and(|(_, leaf)| leaf == "thoughtSignature")
}

/// The window a Gemini candidate's text parts share, from a part's JSON
/// `pointer`. A client joins every text part of a candidate in order
/// (`chunk.text`), within a chunk and across chunks, so they share one
/// window (AGENT-321); one that prints thoughts inline joins those too, so
/// thought parts share it (a thought after the answer blocks under
/// `fail_closed`, see `gemini_parts`). A client reads a candidate by its
/// position (`candidates[0]`), so the window is named by position, not
/// `index` (AGENT-322). `/candidates/0/content/parts/2/text` →
/// `/candidates/0/content/parts/text`.
fn gemini_text(pointer: &str) -> Option<String> {
    let (candidate, field) = pointer.strip_prefix("/candidates/")?.split_once('/')?;
    let (_, leaf) = field.strip_prefix("content/parts/")?.split_once('/')?;
    (leaf == "text").then(|| format!("/candidates/{candidate}/content/parts/text"))
}

/// The lane path of a field later events extend, or `None` for one
/// complete in its event.
/// `chat`: the event is a chat chunk (it has a `choices` array and names
/// no other protocol's event type). A choice's fields are judged as chat
/// whatever the event says; its other fields come whole in a chat chunk
/// and are judged by the event's type otherwise, so neither an empty
/// `choices` nor a `type` turns off another protocol's windows.
fn stream_path(kind: Option<&str>, chat: bool, path: &str) -> Option<String> {
    if path.starts_with("/choices/") {
        // A choice's `delta` (chat) or `text` (completions). `logprobs`
        // and content-filter results are scanned per chunk; an event the
        // text's cut reaches loses its `logprobs` (see `rewrite`).
        let (_, field) = path.strip_prefix("/choices/")?.split_once('/')?;
        // A delta's role, a tool call's id and type come whole.
        if path
            .rsplit('/')
            .next()
            .is_some_and(|last| METADATA.contains(&last))
        {
            return None;
        }
        return (field.starts_with("delta/") || field == "text").then(|| path.to_string());
    }
    if chat {
        return None;
    }
    match kind {
        Some(k) if k.starts_with("response.") => {
            if k.ends_with(".delta") {
                return (path == "/delta").then(|| path.to_string());
            }
            // Clients start a part's text (or a call's arguments) from
            // what `.added` gives, then append the deltas.
            let opening = k.ends_with(".added")
                && matches!(path, "/part/text" | "/part/refusal" | "/item/arguments");
            opening.then(|| "/delta".to_string())
        }
        // A block's opening text is the start of what its deltas extend.
        Some("content_block_start") => match path {
            "/content_block/text" => Some("/delta/text".into()),
            "/content_block/thinking" => Some("/delta/thinking".into()),
            _ => None,
        },
        Some("content_block_delta") => matches!(
            path,
            "/delta/text" | "/delta/thinking" | "/delta/partial_json"
        )
        .then(|| path.to_string()),
        Some(k)
            if k.starts_with("message_")
                || matches!(k, "content_block_stop" | "ping" | "error") =>
        {
            None
        }
        _ => Some(path.to_string()),
    }
}

/// A walk over an event's JSON collecting each non-empty string as
/// (place, lane path, text) and each object key as (place, no path, key).
/// Locations are built in place and copied only for what is collected,
/// and the copies count against `limit`, so deep or long keys cost no
/// more than `limit`.
#[derive(Default)]
struct Walk {
    pointer: String,
    path: String,
    limit: usize,
    used: usize,
    over: bool,
    found: Vec<(Place, Option<String>, String)>,
}

impl Walk {
    fn value(&mut self, value: &Value) {
        if self.over {
            return;
        }
        match value {
            Value::String(text) if !text.is_empty() => {
                if self.spend(self.pointer.len() + self.path.len() + text.len()) {
                    self.found.push((
                        Place::Json(self.pointer.clone()),
                        Some(self.path.clone()),
                        text.clone(),
                    ));
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    self.enter(&i.to_string(), &lanes::element(item, i), item);
                }
            }
            Value::Object(map) => {
                for (key, item) in map {
                    if !key.is_empty() && self.spend(self.pointer.len() + 2 * key.len()) {
                        let place = Place::Key {
                            parent: self.pointer.clone(),
                            key: key.clone(),
                        };
                        self.found.push((place, None, key.clone()));
                    }
                    let token = key.replace('~', "~0").replace('/', "~1");
                    self.enter(&token, &token, item);
                }
            }
            _ => {}
        }
    }

    /// Count `bytes` of copies; false (and stop) past `limit`.
    fn spend(&mut self, bytes: usize) -> bool {
        self.used += bytes;
        self.over |= self.used > self.limit;
        !self.over
    }

    /// Walk `item` at `/pointer_seg` (lane segment `path_seg`).
    fn enter(&mut self, pointer_seg: &str, path_seg: &str, item: &Value) {
        let (p, l) = (self.pointer.len(), self.path.len());
        self.pointer.push('/');
        self.pointer.push_str(pointer_seg);
        self.path.push('/');
        self.path.push_str(path_seg);
        self.value(item);
        self.pointer.truncate(p);
        self.path.truncate(l);
    }
}

/// The lanes this event finishes (`[DONE]` finishes all), in a stream of
/// `scheme`.
pub fn closes(event: &SseEvent, scheme: Option<lanes::Scheme>) -> Vec<Close> {
    if event.data.as_deref() == Some("[DONE]") {
        return vec![Close::All];
    }
    match json(event) {
        Some(value) => lanes::closes(kind(event, &value).as_deref(), scheme, &value),
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

/// Re-serialise `event` with each field's text replaced. JSON data is
/// written from its parsed view, so values a repeated key hid are gone.
pub fn rewrite(event: &SseEvent, edits: &[(Place, String)]) -> Vec<u8> {
    if let Some((_, text)) = edits.iter().find(|(p, _)| *p == Place::Raw) {
        return data_lines(event, text.split('\n').map(str::to_string).collect());
    }
    let Some(mut value) = json(event) else {
        return event.raw.clone();
    };
    for (place, text) in edits {
        if let Place::Json(pointer) = place
            && let Some(slot) = value.pointer_mut(pointer)
        {
            *slot = Value::String(text.clone());
        }
    }
    // Keys after values (whose pointers pass through them), deepest
    // first (a rename moves everything below it).
    let mut keys: Vec<(&str, &str, &str)> = edits
        .iter()
        .filter_map(|(place, text)| match place {
            Place::Key { parent, key } => Some((parent.as_str(), key.as_str(), text.as_str())),
            _ => None,
        })
        .collect();
    keys.sort_by_key(|(parent, ..)| std::cmp::Reverse(parent.matches('/').count()));
    let mut next = HashMap::new();
    for (parent, key, renamed) in keys {
        rename_key(&mut value, parent, key, renamed, &mut next);
    }
    drop_logprobs(&mut value);
    data_lines(event, vec![value.to_string()])
}

/// Rename `key` in the object at `parent`; a name already taken gets a
/// `#<n>` suffix, so no value is overwritten. `next` remembers the next
/// suffix to try per object and name, so many renames stay linear.
fn rename_key(
    value: &mut Value,
    parent: &str,
    key: &str,
    renamed: &str,
    next: &mut HashMap<(String, String), usize>,
) {
    let Some(map) = value.pointer_mut(parent).and_then(Value::as_object_mut) else {
        return;
    };
    let Some(item) = map.remove(key) else {
        return;
    };
    let n = next
        .entry((parent.to_string(), renamed.to_string()))
        .or_insert(1);
    let mut name = renamed.to_string();
    if *n > 1 || map.contains_key(&name) {
        *n = (*n).max(2);
        loop {
            name = format!("{renamed}#{n}");
            *n += 1;
            if !map.contains_key(&name) {
                break;
            }
        }
    } else {
        *n = 2;
    }
    map.insert(name, item);
}

/// Empty every `logprobs` (`null`, or `[]` where it is a list): a
/// rewritten event's tokens, their bytes and alternatives would spell the
/// text its cut removed.
fn drop_logprobs(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if key == "logprobs" {
                    *item = if item.is_array() {
                        Value::Array(Vec::new())
                    } else {
                        Value::Null
                    };
                } else {
                    drop_logprobs(item);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(drop_logprobs),
        _ => {}
    }
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

    /// The text that joins a lane (what later events extend).
    fn streamed(e: &SseEvent) -> Vec<String> {
        extract(e)
            .into_iter()
            .filter(|s| s.lane.is_some())
            .map(|s| s.text)
            .collect()
    }

    /// String values other than protocol metadata.
    fn values(e: &SseEvent) -> Vec<String> {
        extract(e)
            .into_iter()
            .filter(|s| match &s.place {
                Place::Json(p) => !METADATA.contains(&p.rsplit('/').next().unwrap_or("")),
                Place::Raw => true,
                _ => false,
            })
            .map(|s| s.text)
            .collect()
    }

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
        assert_eq!(streamed(&chat), vec!["hi", "{\"q\""]);
        let responses = one(
            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"yo\"}\n\n",
        );
        assert_eq!(streamed(&responses), vec!["yo"]);
        let anthropic = one(
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hey\"}}\n\n",
        );
        assert_eq!(streamed(&anthropic), vec!["hey"]);
        let keys: Vec<_> = extract(&anthropic)
            .into_iter()
            .filter(|s| matches!(s.place, Place::Key { .. }))
            .map(|s| s.text)
            .collect();
        assert!(
            keys.contains(&"delta".to_string()),
            "keys are scanned: {keys:?}"
        );
        assert_eq!(protocol(&anthropic), Some(Protocol::Anthropic));
        assert_eq!(protocol(&chat), Some(Protocol::OpenAi));
    }

    #[test]
    fn non_text_events_join_no_lane() {
        for raw in [
            "event: ping\ndata: {\"type\":\"ping\"}\n\n",
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"role\":\"assistant\"}}\n\n",
            "data: [DONE]\n\n",
            ": keep-alive comment\n\n",
        ] {
            assert!(streamed(&one(raw)).is_empty(), "{raw:?}");
        }
    }

    #[test]
    fn rewrite_replaces_only_the_pointer() {
        let e = one(
            "event: x\nid: 7\ndata: {\"delta\":\"secret\",\"type\":\"response.output_text.delta\"}\n\n",
        );
        let out = String::from_utf8(rewrite(&e, &[(Place::Json("/delta".into()), "[R]".into())]))
            .unwrap();
        assert!(out.starts_with("event: x\nid: 7\ndata: "), "{out}");
        assert!(out.ends_with("\n\n"));
        let again = one(&out);
        assert_eq!(streamed(&again), vec!["[R]"]);
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
        assert_eq!(values(&done), vec!["full answer"]);
        let start = one(
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"hello\"}}\n\n",
        );
        assert_eq!(streamed(&start), vec!["hello"]);
        let plain = one("data: not json at all\n\n");
        assert_eq!(extract(&plain)[0].text, "not json at all");
        let out = String::from_utf8(rewrite(&plain, &[(Place::Raw, "x\ny".into())])).unwrap();
        assert_eq!(out, "data: x\ndata: y\n\n");
        let root = one("data: \"hello\"\n\n");
        assert_eq!(extract(&root)[0].place, Place::Json(String::new()));
        let out = rewrite(&root, &[(Place::Json(String::new()), "[R]".into())]);
        assert_eq!(out, b"data: \"[R]\"\n\n");
        let many: Value = serde_json::json!({"o": (0..5000).map(|n| (format!("k{n}"), Value::from(n)))
            .collect::<serde_json::Map<_, _>>()});
        let many = one(&format!("data: {many}\n\n"));
        let edits: Vec<_> = (0..5000)
            .map(|n| {
                (
                    Place::Key {
                        parent: "/o".into(),
                        key: format!("k{n}"),
                    },
                    "[R]".to_string(),
                )
            })
            .collect();
        let started = std::time::Instant::now();
        let out = rewrite(&many, &edits);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        let v: Value = serde_json::from_str(
            one(std::str::from_utf8(&out).unwrap())
                .data
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(v["o"].as_object().unwrap().len(), 5000);
        let keyed = one("data: {\"a\":{\"k1\":1,\"k2\":{\"k1\":\"v\"}}}\n\n");
        let edits = [
            (
                Place::Key {
                    parent: "/a".into(),
                    key: "k1".into(),
                },
                "[R]".into(),
            ),
            (
                Place::Key {
                    parent: "/a/k2".into(),
                    key: "k1".into(),
                },
                "[R]".into(),
            ),
            (
                Place::Key {
                    parent: "/a".into(),
                    key: "k2".into(),
                },
                "[R]".into(),
            ),
        ];
        let v: Value = serde_json::from_str(
            one(std::str::from_utf8(&rewrite(&keyed, &edits)).unwrap())
                .data
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"a": {"[R]": 1, "[R]#2": {"[R]": "v"}}})
        );
    }
}
