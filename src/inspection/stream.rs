//! AGENT-265 — inspecting a server-sent event stream as it passes.
//!
//! Events are parsed as they arrive. Each text field goes, in order, to
//! the window of the output it belongs to (its lane: a chat choice, a tool
//! call, a content block; see [`super::lanes`]), so a match split across
//! one output's deltas stays contiguous however outputs interleave. Under
//! `pass` or `flag` every event is forwarded the moment it is complete;
//! hits are only audited. Under `redact` or `block` an event is held until
//! no future match can reach back into its text (each field's text ends
//! before its lane's `base`, or its lane is finished; a field complete in
//! its event, a snapshot, is scanned alone and never waits), so a secret split
//! across many deltas is caught before any part of it is sent. A redact
//! rewrites the held events' text fields (the marker in the event where
//! the match starts, the rest removed); a block drops what is held, sends
//! one protocol-shaped error event, and ends the stream. Every string and
//! object key in an event's JSON (aggregates as well as deltas) is
//! scanned.
//!
//! An event longer than `max_scan_bytes`, or held text or events past it,
//! can't be judged in bounds: under `fail_closed` the stream is blocked;
//! under `fail_open` the oldest held event is released early, or (an
//! oversized event) the rest of the stream passes through unscanned.

use super::lanes::{Close, Lane};
use super::sse::{self, Protocol, SseEvent, SseParser, TextSpan};
use super::window::{Carried, TextWindow, WindowHit};
use super::{
    Direction, DirectionPolicy, HitRecord, MAX_AUDITED_HITS, OnError, Report, Scanner, Verdict,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Distinct hits remembered for deduplication; past it, new hits are
/// counted as dropped without being remembered.
const MAX_SEEN: usize = 4 * MAX_AUDITED_HITS;

/// Unfinished outputs given their own window under `fail_open`; more
/// share one, so memory is bounded: each window can hold up to
/// `max_scan_bytes` there (an eighth more under `flag` or `pass` once it
/// has overflowed, AGENT-315). A finished output's window drops its text.
const MAX_LANES: usize = 32;

/// The same limit under `fail_closed`, where the text all windows hold
/// is already limited to `max_scan_bytes` (`over_cap` blocks past it)
/// and a trimmed window gives memory back, so more lanes add little.
/// Each parallel tool call takes two lanes, so 32 blocked about 15 of
/// them (AGENT-273).
const MAX_LANES_CLOSED: usize = 256;

/// Outputs remembered in one stream (finished ones too, so text after
/// a finish is caught); more share one window.
const MAX_OUTPUTS: usize = 1024;

/// Clean texts remembered, and the longest remembered.
const MAX_CLEAN: usize = 256;
const MAX_CLEAN_TEXT: usize = 256;

/// Ids at or past this name a field scanned alone, not a lane.
const WHOLE: usize = 1 << 48;

/// What to send the agent after one push, and whether the stream is over.
#[derive(Debug, Default)]
pub struct Step {
    pub out: Vec<Vec<u8>>,
    pub ended: bool,
}

/// Byte ranges of one text field to cut, with the marker to leave at a
/// cut where a match starts.
type Cuts = Vec<(usize, usize, Option<String>)>;

/// A text field of a held event: the span, its lane's index and where its
/// text starts in that lane.
struct Field {
    span: TextSpan,
    lane: usize,
    start: usize,
}

struct Held {
    event: SseEvent,
    fields: Vec<Field>,
    cuts: Vec<Cuts>,
    /// Bytes it keeps: the raw event and each field's copies.
    cost: usize,
}

impl Field {
    /// Bytes this field's copies keep: text, pointer and lane path.
    fn cost(&self) -> usize {
        let place = match &self.span.place {
            sse::Place::Json(pointer) => pointer.len(),
            sse::Place::Key { parent, key } => parent.len() + key.len(),
            _ => 0,
        };
        self.span.text.len() + place + self.span.lane.as_ref().map_or(0, |l| l.path.len())
    }
}

struct LaneState {
    lane: Lane,
    window: TextWindow,
    /// The protocol said this output is finished: nothing more extends it.
    done: bool,
    /// A later output of its join group began from this one's text: what
    /// it is sent after that joins no output a client joins (AGENT-329).
    superseded: bool,
    /// The scan across this output's start and the end of the one its
    /// clients join it after, while a match could still cross it.
    bridge: Option<Bridge>,
    /// Where the text already sent of it ends, past trailing whitespace
    /// (AGENT-330).
    sent: usize,
}

/// AGENT-329: a second window over a joined output's start, beginning with
/// the previous output's kept tail. The output keeps its own window, so
/// what it alone holds is judged as before (a key right after a word in
/// the previous output still starts at a word boundary in its own); the
/// bridge reports only matches crossing the join, in the output's offsets.
struct Bridge {
    window: TextWindow,
    /// Bytes of carried tail before the output's first byte.
    seed: usize,
}

impl Bridge {
    /// Matches crossing the join, moved into `lane`'s offsets (a match
    /// starting in the carried tail starts at the output's start).
    fn crossing(&self, lane: usize, found: Vec<WindowHit>) -> Vec<LaneHit> {
        found
            .into_iter()
            .filter(|h| h.start < self.seed && h.end > self.seed)
            .map(|h| LaneHit {
                lane,
                hit: WindowHit {
                    start: 0,
                    end: h.end - self.seed,
                    fresh: h.fresh.max(self.seed) - self.seed,
                    ..h
                },
            })
            .collect()
    }

    /// No match can cross the join any more: the bridge's last scan kept
    /// none of the carried tail.
    fn spent(&self) -> bool {
        self.window.base() >= self.seed
    }
}

/// A hit with the lane it was found in.
struct LaneHit {
    lane: usize,
    hit: WindowHit,
}

pub struct StreamInspector {
    parser: SseParser,
    scanners: Vec<Arc<dyn Scanner>>,
    lanes: Vec<LaneState>,
    by_lane: HashMap<Lane, usize>,
    on_hit: Verdict,
    on_error: OnError,
    hold: bool,
    held: VecDeque<Held>,
    held_bytes: usize,
    max_held: usize,
    protocol: Protocol,
    report: Report,
    seen: HashSet<(String, String, String)>,
    /// Where each recorded hit lies (lane, start, end, flag-only),
    /// parallel to `report.hits`.
    recorded: Vec<(usize, usize, usize, bool)>,
    ended: bool,
    hold_overflowed: bool,
    /// Past an oversized event under `fail_open`: forward bytes as is.
    passthrough: bool,
    /// Fields scanned alone so far (their ids count up from `WHOLE`).
    wholes: usize,
    /// Bytes of lane paths remembered, held to `max_scan_bytes`.
    lane_bytes: usize,
    /// The highest tool-call index seen in each chat choice (AGENT-317).
    last_call: HashMap<String, i64>,
    /// The tags of each join group's latest output (AGENT-329).
    last_join: HashMap<JoinGroup, Vec<i64>>,
    /// Whether each chat array's elements came by `index` (AGENT-317).
    indexed: HashMap<String, bool>,
    /// Gemini candidates (by position) whose answer text has started.
    answered: HashSet<usize>,
    /// Short texts scanned alone and found clean.
    clean: HashSet<String>,
    /// A configured scanner can't judge streams and `on_error` is
    /// `fail_closed`: the stream is blocked before anything is sent.
    unjudged: bool,
    /// The protocol scheme the stream's first protocol event named.
    scheme: Option<super::lanes::Scheme>,
    /// Whether the stream's first JSON event was a JSON-RPC message.
    jsonrpc: Option<bool>,
    /// The tail of the last finished output of each join group, for the
    /// next output of that group to start from (AGENT-329).
    carry: HashMap<JoinGroup, Carried>,
}

/// Outputs a client joins into one text, whatever their indexes: an
/// Anthropic message's text blocks, and Responses content parts (the SDK's
/// `output_text`). Only these: tool inputs and arguments, thinking and
/// reasoning summaries are not joined by clients, and an allow-list keeps
/// an upstream from making a group of every key it invents, which would
/// keep a tail per group.
type JoinGroup = &'static str;

fn join_group(lane: &Lane) -> Option<JoinGroup> {
    let names: Vec<&str> = lane.tags.iter().map(|(t, _)| *t).collect();
    match (lane.path.as_str(), names.as_slice()) {
        ("/delta/text", ["i"]) => Some("anthropic text"),
        ("/delta", ["o", "c"]) => Some("responses content"),
        _ => None,
    }
}

impl StreamInspector {
    pub fn new(policy: &DirectionPolicy) -> Self {
        let mut inspector = Self::build(policy);
        // A scanner that does not take part in streams (a sidecar scores
        // whole texts, not a sliding tail) leaves this stream unjudged by
        // it: that is an inspection error, so `on_error` decides.
        let skipped: Vec<&str> = policy
            .scanners
            .iter()
            .filter(|s| !s.streams())
            .map(|s| s.id())
            .collect();
        if !skipped.is_empty() {
            inspector.report.error = Some(format!(
                "{} cannot inspect a streamed response",
                skipped.join(", ")
            ));
            inspector.unjudged = policy.on_error == OnError::FailClosed;
        }
        inspector
    }

    fn build(policy: &DirectionPolicy) -> Self {
        Self {
            parser: SseParser::with_cap(policy.max_scan_bytes),
            scanners: policy
                .scanners
                .iter()
                .filter(|s| s.streams())
                .cloned()
                .collect(),
            lanes: Vec::new(),
            by_lane: HashMap::new(),
            on_hit: policy.on_hit,
            on_error: policy.on_error,
            hold: policy.on_hit >= Verdict::Redact,
            held: VecDeque::new(),
            held_bytes: 0,
            max_held: policy.max_scan_bytes,
            protocol: Protocol::OpenAi,
            report: Report::new(Direction::Response),
            seen: HashSet::new(),
            recorded: Vec::new(),
            ended: false,
            hold_overflowed: false,
            passthrough: false,
            wholes: 0,
            lane_bytes: 0,
            last_call: HashMap::new(),
            last_join: HashMap::new(),
            indexed: HashMap::new(),
            answered: HashSet::new(),
            clean: HashSet::new(),
            unjudged: false,
            scheme: None,
            jsonrpc: None,
            carry: HashMap::new(),
        }
    }

    pub fn report(&self) -> &Report {
        &self.report
    }

    /// Blocked before any event arrives: a scanner that cannot take part
    /// in streams under `fail_closed`. The caller can refuse the stream
    /// outright instead of sending headers and an error event (AGENT-278).
    pub fn refused_up_front(&self) -> bool {
        self.unjudged
    }

    /// A window or the held events overflowed their cap at least once.
    pub fn hold_overflowed(&self) -> bool {
        self.hold_overflowed || self.lanes.iter().any(|l| l.window.overflowed())
    }

    pub fn push(&mut self, chunk: &[u8]) -> Step {
        let mut step = Step::default();
        if self.ended {
            step.ended = true;
            return step;
        }
        // The proxy checks `refused_up_front` and never feeds such a
        // stream, so this guards other callers: block, never pass it.
        if self.unjudged {
            self.block(&mut step);
            self.ended = true;
            return step;
        }
        if self.passthrough {
            step.out.push(chunk.to_vec());
            return step;
        }
        let mut events = self.parser.push(chunk).into_iter();
        while let Some(event) = events.next() {
            self.event(event, &mut step);
            if step.ended {
                self.ended = true;
                return step;
            }
            if self.passthrough {
                step.out.extend(events.by_ref().map(|e| e.raw));
            }
        }
        if self.parser.overflowed() && !self.passthrough {
            self.oversized(None, &mut step);
        } else if self.passthrough
            && let Some(rest) = self.parser.finish()
        {
            step.out.push(rest.raw);
        }
        step
    }

    /// An event too big to judge within `max_scan_bytes`: `current`, or
    /// (`None`) the one the parser overflowed on.
    fn oversized(&mut self, current: Option<SseEvent>, step: &mut Step) {
        self.report.skipped = Some(super::SkipReason::Oversize);
        if self.on_error == OnError::FailClosed {
            self.block(step);
            self.ended = true;
            return;
        }
        // AGENT-273: what is held may not have been scanned yet (a window
        // scans once enough text is new). Judge it, so its cuts are made,
        // before it goes out.
        self.close(&[Close::All], step);
        if step.ended {
            self.ended = true;
            return;
        }
        while let Some(h) = self.held.pop_front() {
            step.out.push(render(&h));
        }
        match current {
            // `push` forwards the rest of its batch, then the parser's.
            Some(event) => step.out.push(event.raw),
            None => step.out.extend(self.parser.finish().map(|rest| rest.raw)),
        }
        self.passthrough = true;
    }

    /// AGENT-273: the upstream broke off or the agent left. Judge what is
    /// held for the audit, but send none of it. A half-received last event
    /// is not an event: judging it could block a stream that was simply
    /// cut off.
    pub fn abandon(&mut self) -> Step {
        if !self.ended {
            let _ = self.parser.finish();
        }
        let mut step = self.finish();
        step.out.clear();
        step
    }

    /// The upstream ended: judge what is left, then send what is held.
    pub fn finish(&mut self) -> Step {
        let mut step = Step::default();
        if self.ended {
            step.ended = true;
            return step;
        }
        // As in `push`: unreachable from the proxy, kept fail-closed.
        if self.unjudged {
            self.block(&mut step);
            self.ended = true;
            return step;
        }
        if !self.passthrough {
            // An unterminated last event is still an event: judge it.
            if let Some(rest) = self.parser.finish() {
                self.event(rest, &mut step);
            }
            // Past an oversize last event the rest went out unscanned.
            if !step.ended && !self.passthrough {
                self.close(&[Close::All], &mut step);
            }
            if step.ended {
                self.ended = true;
                return step;
            }
        }
        while let Some(h) = self.held.pop_front() {
            step.out.push(render(&h));
        }
        self.ended = true;
        step.ended = true;
        step
    }

    /// A window for one output. With no events held (`pass`, `flag`) its
    /// hits need only be found, so it keeps batching its scans past its
    /// cap (AGENT-315).
    fn window(&self) -> TextWindow {
        let window = TextWindow::new(self.scanners.clone(), self.max_held);
        if self.hold {
            window
        } else {
            window.batching_past_cap()
        }
    }

    /// The lane `lane`'s index, made on first use. Past `MAX_LANES`
    /// (`MAX_LANES_CLOSED` under `fail_closed`) unfinished outputs, or
    /// `MAX_OUTPUTS` in all, or lane paths past `max_scan_bytes`, new
    /// outputs share one window, which can split a match: that is an
    /// overflow (`None` under `fail_closed`). A finished output written to
    /// again counts as a new one under `fail_open` (AGENT-273), so reopened
    /// outputs can't hold more than `MAX_LANES` windows; under
    /// `fail_closed` that text blocks the stream anyway.
    fn lane(&mut self, lane: &Lane) -> Option<usize> {
        let live = self.lanes.iter().filter(|l| !l.done).count();
        let max_lanes = match self.on_error {
            OnError::FailClosed => MAX_LANES_CLOSED,
            OnError::FailOpen => MAX_LANES,
        };
        if let Some(&i) = self.by_lane.get(lane) {
            let reopens = self.lanes[i].done && self.on_error == OnError::FailOpen;
            if !(reopens && live + 1 >= max_lanes) {
                return Some(i);
            }
        }
        let shared = Lane {
            path: "*".into(),
            tags: Vec::new(),
        };
        let full = live + 1 >= max_lanes
            || self.lanes.len() + 1 >= MAX_OUTPUTS
            || self.lane_bytes + lane.path.len() > self.max_held;
        let lane = if full {
            if self.on_error == OnError::FailClosed {
                return None;
            }
            self.hold_overflowed = true;
            // The shared window takes no tail; a later output of the group
            // must not start from one no longer next to it.
            if let Some(group) = join_group(lane) {
                self.carry.remove(group);
            }
            &shared
        } else {
            lane
        };
        if let Some(&i) = self.by_lane.get(lane) {
            return Some(i);
        }
        self.lane_bytes += lane.path.len();
        let bridge = join_group(lane)
            .and_then(|g| self.carry.remove(g))
            .map(|tail| {
                let seed = tail.len();
                let mut window = self.window();
                window.seed(tail);
                Bridge { window, seed }
            });
        self.lanes.push(LaneState {
            lane: lane.clone(),
            window: self.window(),
            done: false,
            superseded: false,
            bridge,
            sent: 0,
        });
        let i = self.lanes.len() - 1;
        self.by_lane.insert(lane.clone(), i);
        Some(i)
    }

    /// A chat tool call first seen below a higher-numbered call of its
    /// choice, or with a negative index, or a chat array addressed both
    /// by `index` and by position (AGENT-317). Its lane is new, so
    /// a match split between it and the call before is in no one window,
    /// while a client merging calls by position joins them. Only matters
    /// where events are held under `fail_closed`.
    /// Tracked only there, so the map grows only with lanes, which are
    /// bounded (`lane` blocks past them under `fail_closed`).
    fn out_of_order(&mut self, lane: &Lane) -> Option<&'static str> {
        if !self.hold || self.on_error != OnError::FailClosed {
            return None;
        }
        // An element with no `index` gets a positional lane; mixed with
        // indexed ones, a client could merge it into another output.
        for (array, by_index) in super::lanes::chat_addressing(&lane.path) {
            if *self.indexed.entry(array.to_string()).or_insert(by_index) != by_index {
                return Some("stream outputs addressed both by index and by position");
            }
            // With no index, only the first element of each chunk's array
            // is unambiguous: a client may merge index-less entries into
            // one slot, joining a later element to the first.
            if !by_index && !lane.path[array.len()..].starts_with("0/") {
                return Some("stream outputs addressed only by position");
            }
        }
        let (calls, n) = super::lanes::tool_call(&lane.path)?;
        let last = self.last_call.get(calls).copied();
        if !self.by_lane.contains_key(lane) && (n < 0 || last.is_some_and(|m| n < m)) {
            return Some("stream tool call out of order");
        }
        if last.is_none_or(|m| n > m) {
            self.last_call.insert(calls.to_string(), n);
        }
        None
    }

    fn event(&mut self, event: SseEvent, step: &mut Step) {
        if let Some(p) = sse::protocol(&event) {
            self.protocol = p;
        }
        let mut fields = Vec::new();
        let mut hits = Vec::new();
        if !self.fix_scheme(&event, step) {
            return;
        }
        if !self.fix_jsonrpc(&event, step) {
            return;
        }
        let jsonrpc = self.jsonrpc == Some(true);
        let Some(spans) = sse::extract_within(&event, self.max_held, self.scheme, jsonrpc) else {
            return self.oversized(Some(event), step);
        };
        // Clients read a loose index (`"1.0"`, `1e0`, past 2^53) in
        // different ways, so no lane can match all of them (AGENT-317).
        if self.hold
            && self.on_error == OnError::FailClosed
            && !sse::indexes_are_plain(&event, self.scheme)
        {
            self.note_error("stream output index is not a plain integer".into());
            return self.block(step);
        }
        if self.hold && self.on_error == OnError::FailClosed {
            // AGENT-322: a thought after its candidate's answer would sit
            // between two pieces of answer a client joins without it.
            let Some(parts) = sse::gemini_parts(&event) else {
                self.note_error("stream Gemini candidate or part reads two ways".into());
                return self.block(step);
            };
            for (candidate, thought) in parts {
                if thought && self.answered.contains(&candidate) {
                    self.note_error("stream Gemini thought after its answer".into());
                    return self.block(step);
                }
                if !thought {
                    self.answered.insert(candidate);
                }
            }
        }
        if spans
            .iter()
            .any(|s| s.place == sse::Place::View { json: true })
            && self.on_error == OnError::FailClosed
        {
            self.note_error("stream event data is JSON that does not parse".into());
            return self.block(step);
        }
        if spans.iter().any(|s| s.place == sse::Place::Hidden) {
            // A hidden value is scanned in its event only: one split
            // across events would be missed.
            if self.on_error == OnError::FailClosed {
                self.note_error("stream event repeats a JSON key".into());
                return self.block(step);
            }
            self.hold_overflowed = true;
        }
        for span in spans {
            let Some(key) = &span.lane else {
                let Some(id) = self.whole(&span, &mut hits, step) else {
                    return;
                };
                fields.push(Field {
                    span,
                    lane: id,
                    start: 0,
                });
                continue;
            };
            if let Some(why) = self.out_of_order(key) {
                self.note_error(why.into());
                return self.block(step);
            }
            // A new output of a join group, in order, takes the tail of the
            // group's latest output, which clients join just before it
            // (AGENT-329); one out of order takes none (AGENT-328). The
            // lender keeps its window, so nothing it holds is lost; text
            // sent to it later joins nothing, so it is an interleave
            // (below).
            let mut set_aside = None;
            if !self.by_lane.contains_key(key)
                && let Some(group) = join_group(key)
            {
                // Clients join a group's outputs in index order: one
                // starting below an earlier one joins before it.
                let at: Vec<i64> = key.tags.iter().map(|&(_, v)| v).collect();
                let in_order = self.last_join.get(group).is_none_or(|last| at > *last);
                let open: Vec<usize> = (0..self.lanes.len())
                    .filter(|&i| {
                        let l = &self.lanes[i];
                        !l.done && !l.superseded && join_group(&l.lane) == Some(group)
                    })
                    .collect();
                if !in_order {
                    if self.on_error == OnError::FailClosed {
                        self.note_error("joined stream outputs out of order".into());
                        return self.block(step);
                    }
                    // It joins before the group's latest output: it takes
                    // no tail, and leaves that output open and its tail kept
                    // for the next one, which clients join after it
                    // (AGENT-328).
                    self.hold_overflowed = true;
                    set_aside = self.carry.remove(group).map(|tail| (group, tail));
                } else {
                    // In order, it follows the group's latest output: only
                    // that one lends, wherever it is among the open ones,
                    // not an out-of-order one still open (AGENT-328).
                    let lender = open
                        .iter()
                        .copied()
                        .find(|&i| self.is_latest(group, &self.lanes[i].lane));
                    self.last_join.insert(group, at);
                    if let Some(latest) = lender {
                        self.lend_tail(group, latest);
                    }
                    for i in open {
                        self.lanes[i].superseded = true;
                    }
                }
            }
            let Some(lane) = self.lane(key) else {
                self.note_error("more stream outputs than can be inspected".into());
                return self.block(step);
            };
            if let Some((group, tail)) = set_aside {
                self.carry.insert(group, tail);
            }
            let state = &mut self.lanes[lane];
            if state.done {
                // Its output was said to be finished, and its held events
                // may already be out: a match spanning the two is missed.
                if self.on_error == OnError::FailClosed {
                    self.note_error("stream text after its output finished".into());
                    return self.block(step);
                }
                self.hold_overflowed = true;
                state.done = false;
            }
            if state.superseded {
                // A later output its clients join after it already took its
                // tail: a match through what comes now is in no one window.
                if self.on_error == OnError::FailClosed {
                    self.note_error("joined stream outputs interleaved".into());
                    return self.block(step);
                }
                self.hold_overflowed = true;
                state.superseded = false;
            }
            let start = state.window.end();
            let found = state.window.push(&span.text);
            let overflowed = state.window.overflowed();
            if !self.scanned(lane, found, overflowed, &mut hits, step) {
                return;
            }
            if !self.bridge_push(lane, &span.text, &mut hits, step) {
                return;
            }
            fields.push(Field { span, lane, start });
        }
        if self.over_cap(step) {
            return;
        }
        let mut closes = sse::closes(&event, self.scheme);
        // A later tool call finishing the earlier ones only matters where
        // events are held and can't be released early: under `pass` or
        // `flag` nothing is held, and under `fail_open` held events go
        // early (audited) while an interleaving upstream would split a
        // match there.
        if self.on_error == OnError::FailOpen || !self.hold {
            closes.retain(|c| !matches!(c, Close::Earlier { .. }));
        }
        let verdict = self.judge(&hits, step);
        if step.ended {
            return;
        }
        if !self.hold {
            step.out.push(event.raw);
            self.close(&closes, step);
            return;
        }
        let cost = event.raw.len() + fields.iter().map(Field::cost).sum::<usize>();
        self.held_bytes += cost;
        let cuts = vec![Cuts::new(); fields.len()];
        self.held.push_back(Held {
            event,
            fields,
            cuts,
            cost,
        });
        if verdict == Verdict::Redact {
            let late = self.late(&hits);
            self.cut_all(&hits);
            if late || self.unrewritable() {
                self.report.redaction_incomplete = true;
                return self.block(step);
            }
        }
        self.settle_newest();
        self.close(&closes, step);
        if !step.ended {
            self.release(step);
        }
    }

    /// Record why inspection is incomplete. The first reason stays
    /// (AGENT-278): under `fail_open` a later scan error must not hide
    /// that a sidecar never ran.
    fn note_error(&mut self, why: String) {
        self.report.error.get_or_insert(why);
    }

    /// Fix the stream's protocol scheme on its first event that names one.
    /// An event naming another (or whose name and `type` disagree) could be
    /// read two ways by clients: false when that blocked the stream.
    fn fix_scheme(&mut self, event: &SseEvent, step: &mut Step) -> bool {
        let found = sse::scheme(event);
        let changed = matches!((self.scheme, found), (Some(a), Some(b)) if a != b);
        if changed || sse::names_disagree(event) || sse::seeds_output(event) {
            if self.on_error == OnError::FailClosed {
                self.note_error(if changed || sse::names_disagree(event) {
                    "stream event names another protocol".into()
                } else {
                    "stream snapshot already carries output text".into()
                });
                self.block(step);
                return false;
            }
            self.hold_overflowed = true;
        }
        if self.scheme.is_none() {
            self.scheme = found;
        }
        true
    }

    /// Fix whether the stream is JSON-RPC on its first JSON event. A
    /// JSON-RPC stream's later non-JSON-RPC event is another protocol:
    /// under `fail_closed` it blocks (false), under `fail_open` it keeps
    /// its windows and is audited (AGENT-273).
    fn fix_jsonrpc(&mut self, event: &SseEvent, step: &mut Step) -> bool {
        if self.jsonrpc == Some(false) {
            return true;
        }
        let Some(this) = sse::is_jsonrpc(event) else {
            return true;
        };
        match self.jsonrpc {
            None => self.jsonrpc = Some(this),
            Some(true) if !this => {
                if self.on_error == OnError::FailClosed {
                    self.note_error("stream event names another protocol".into());
                    self.block(step);
                    return false;
                }
                self.hold_overflowed = true;
            }
            _ => {}
        }
        true
    }

    /// Scan a field complete in its event on its own; its id, or `None`
    /// when the stream was blocked.
    fn whole(
        &mut self,
        span: &TextSpan,
        hits: &mut Vec<LaneHit>,
        step: &mut Step,
    ) -> Option<usize> {
        let id = WHOLE + self.wholes;
        self.wholes += 1;
        // Ids, model names and keys repeat in every event: a short text
        // already found clean is clean again.
        if self.clean.contains(&span.text) {
            return Some(id);
        }
        let mut window = TextWindow::new(self.scanners.clone(), self.max_held);
        let found = window.push(&span.text).and_then(|mut found| {
            found.extend(window.flush()?);
            Ok(found)
        });
        let overflowed = window.overflowed();
        let clean = matches!(&found, Ok(f) if f.is_empty()) && !overflowed;
        if clean && span.text.len() <= MAX_CLEAN_TEXT && self.clean.len() < MAX_CLEAN {
            self.clean.insert(span.text.clone());
        }
        self.scanned(id, found, overflowed, hits, step)
            .then_some(id)
    }

    /// Take one window result (`overflowed`: the window passed its cap);
    /// false when the stream was blocked.
    fn scanned(
        &mut self,
        lane: usize,
        found: Result<Vec<WindowHit>, super::ScanError>,
        overflowed: bool,
        hits: &mut Vec<LaneHit>,
        step: &mut Step,
    ) -> bool {
        match found {
            Ok(found) => hits.extend(found.into_iter().map(|hit| LaneHit { lane, hit })),
            Err(e) => {
                self.note_error(e.0);
                if self.on_error == OnError::FailClosed {
                    self.block(step);
                    return false;
                }
            }
        }
        if overflowed && self.on_error == OnError::FailClosed {
            self.note_error("stream text held past max_scan_bytes".into());
            self.block(step);
            return false;
        }
        true
    }

    /// Feed `text` (just pushed to `lane`'s own window) to the lane's
    /// bridge, scanning at once, and judge only what crosses the join. The
    /// bridge goes once nothing can cross it.
    fn bridge_push(
        &mut self,
        lane: usize,
        text: &str,
        hits: &mut Vec<LaneHit>,
        step: &mut Step,
    ) -> bool {
        let Some(bridge) = self.lanes[lane].bridge.as_mut() else {
            return true;
        };
        let found = bridge.window.push(text).map(|f| bridge.crossing(lane, f));
        let overflowed = bridge.window.overflowed();
        if bridge.spent() {
            self.lanes[lane].bridge = None;
        }
        self.bridged(found, overflowed, hits, step)
    }

    /// Take a bridge's result, as `scanned` does a window's. An overflow
    /// is audited even under `fail_open`: the bridge goes, its flag with it.
    /// A new match to redact across the join cannot be removed whole: its
    /// start went out with the earlier output, so the stream is blocked
    /// (`redaction_incomplete`). A match the earlier output reported, now
    /// grown into this one, is cut here as well.
    fn bridged(
        &mut self,
        found: Result<Vec<LaneHit>, super::ScanError>,
        overflowed: bool,
        hits: &mut Vec<LaneHit>,
        step: &mut Step,
    ) -> bool {
        self.hold_overflowed |= overflowed;
        let found = found.map(|f| {
            let split = f
                .iter()
                .any(|h| h.hit.new && self.verdict_of(&h.hit) == Verdict::Redact);
            hits.extend(f);
            if split {
                // The block ends the stream: audit everything found with it.
                self.record(hits);
                self.report.redaction_incomplete = true;
            }
            split
        });
        if let Ok(true) = found {
            self.block(step);
            return false;
        }
        self.scanned(0, found.map(|_| Vec::new()), overflowed, hits, step)
    }

    /// `lane` is the latest in-order output of `group`.
    fn is_latest(&self, group: JoinGroup, lane: &Lane) -> bool {
        self.last_join.get(group).is_some_and(|last| {
            lane.tags.len() == last.len() && lane.tags.iter().zip(last).all(|(&(_, v), l)| v == *l)
        })
    }

    /// `lane`'s tail for the next output of its group, if not empty. With
    /// a bridge, that is the bridge's: the earlier outputs' kept tail and
    /// then this one's text, so a match can cross a short output too.
    fn lend_tail(&mut self, group: JoinGroup, lane: usize) {
        let state = &self.lanes[lane];
        let tail = match &state.bridge {
            None => state.window.carried(),
            Some(b) => b.window.carried(),
        };
        if !tail.is_empty() {
            self.carry.insert(group, tail);
        }
    }

    /// All lanes together hold more text than `max_scan_bytes`.
    fn over_cap(&mut self, step: &mut Step) -> bool {
        // Carried tails and bridges count too: text held for joined outputs.
        let held: usize = self
            .lanes
            .iter()
            .map(|l| l.window.held() + l.bridge.as_ref().map_or(0, |b| b.window.held()))
            .sum::<usize>()
            + self.carry.values().map(Carried::len).sum::<usize>();
        if held <= self.max_held {
            return false;
        }
        self.hold_overflowed = true;
        self.carry.clear();
        if self.on_error == OnError::FailClosed {
            self.note_error("stream text held past max_scan_bytes".into());
            self.block(step);
            return true;
        }
        false
    }

    /// Record `hits`; block when one calls for it. The strongest verdict.
    fn judge(&mut self, hits: &[LaneHit], step: &mut Step) -> Verdict {
        let verdict = self.record(hits);
        if verdict == Verdict::Block {
            self.block(step);
        }
        verdict
    }

    /// Drop the newest held event's fields scanned alone and left uncut:
    /// their cuts were all decided in their own event, so only the
    /// fields later text can reach (and those to rewrite) are kept.
    fn settle_newest(&mut self) {
        let Some(h) = self.held.back_mut() else {
            return;
        };
        let (fields, cuts): (Vec<_>, Vec<_>) = std::mem::take(&mut h.fields)
            .into_iter()
            .zip(std::mem::take(&mut h.cuts))
            .filter(|(f, cuts)| f.lane < WHOLE || !cuts.is_empty())
            .unzip();
        h.fields = fields;
        h.cuts = cuts;
        let cost = h.event.raw.len() + h.fields.iter().map(Field::cost).sum::<usize>();
        self.held_bytes = self.held_bytes - h.cost + cost;
        h.cost = cost;
    }

    /// The newest held event has a cut no rewrite can make.
    fn unrewritable(&self) -> bool {
        self.held.back().is_some_and(|h| {
            h.fields.iter().zip(&h.cuts).any(|(f, cuts)| {
                matches!(f.span.place, sse::Place::View { .. }) && !cuts.is_empty()
            })
        })
    }

    /// A hit to redact begins, past what earlier reports of it covered, in
    /// text its lane already sent (released early under `fail_open`), so
    /// no cut can remove it whole (AGENT-330).
    fn late(&self, hits: &[LaneHit]) -> bool {
        hits.iter().any(|h| {
            h.lane < WHOLE
                && self.verdict_of(&h.hit) == Verdict::Redact
                && h.hit.fresh < self.lanes[h.lane].sent
        })
    }

    /// Mark every redact-level hit for removal in the events it covers.
    fn cut_all(&mut self, hits: &[LaneHit]) {
        for h in hits {
            if self.verdict_of(&h.hit) == Verdict::Redact {
                self.cut(h);
            }
        }
    }

    /// Finish the lanes `closes` covers: scan what they hold unscanned
    /// and judge it, so their held events can go.
    fn close(&mut self, closes: &[Close], step: &mut Step) {
        if closes.is_empty() {
            return;
        }
        let covered: Vec<usize> = (0..self.lanes.len())
            .filter(|&lane| closes.iter().any(|c| c.covers(&self.lanes[lane].lane)))
            .collect();
        self.finish_lanes(&covered, step);
    }

    /// Finish the lanes `lanes`: scan and judge what they hold unscanned,
    /// keep each joined output's tail for the next one of its group, and
    /// drop their text.
    fn finish_lanes(&mut self, lanes: &[usize], step: &mut Step) {
        if lanes.is_empty() {
            return;
        }
        let mut hits = Vec::new();
        for &lane in lanes {
            let found = self.lanes[lane].window.flush();
            let overflowed = self.lanes[lane].window.overflowed();
            if !self.scanned(lane, found, overflowed, &mut hits, step) {
                return;
            }
            // What the bridge holds unscanned may still cross the join.
            let bridged = self.lanes[lane].bridge.as_mut().map(|bridge| {
                let found = bridge.window.flush().map(|f| bridge.crossing(lane, f));
                (found, bridge.window.overflowed())
            });
            let state = &self.lanes[lane];
            // A superseded output's successor already took its tail, and
            // only the group's latest output is followed by the next one.
            if let Some(group) = join_group(&state.lane)
                && !state.superseded
                && self.is_latest(group, &state.lane)
            {
                self.lend_tail(group, lane);
            }
            self.lanes[lane].bridge = None;
            if let Some((found, overflowed)) = bridged
                && !self.bridged(found, overflowed, &mut hits, step)
            {
                return;
            }
            let state = &mut self.lanes[lane];
            state.done = true;
            state.window.release_text();
        }
        let verdict = self.judge(&hits, step);
        if !step.ended && verdict == Verdict::Redact {
            if self.late(&hits) {
                self.report.redaction_incomplete = true;
                return self.block(step);
            }
            self.cut_all(&hits);
        }
    }

    fn verdict_of(&self, hit: &WindowHit) -> Verdict {
        if hit.flag_only {
            self.on_hit.min(Verdict::Flag)
        } else {
            self.on_hit
        }
    }

    /// Count new hits into the report; the strongest verdict among them.
    /// A flag-only hit seen on a partial match (entropy over the first
    /// characters of a key) gives way to the named rule that later covers
    /// it, as it would in a buffered scan.
    fn record(&mut self, hits: &[LaneHit]) -> Verdict {
        let mut verdict = Verdict::Pass;
        for LaneHit { lane, hit } in hits {
            let v = self.verdict_of(hit);
            verdict = verdict.max(v);
            if !hit.flag_only {
                self.drop_superseded(*lane, hit);
            } else if self
                .recorded
                .iter()
                .any(|&(l, a, b, _)| l == *lane && a < hit.end && hit.start < b)
            {
                continue;
            }
            let key = (hit.scanner.clone(), hit.rule.clone(), hit.sha256.clone());
            if !hit.new || self.seen.contains(&key) {
                continue;
            }
            if self.seen.len() < MAX_SEEN {
                self.seen.insert(key);
            }
            self.report.verdict = self.report.verdict.max(v);
            if self.report.hits.len() < MAX_AUDITED_HITS {
                self.report.hits.push(HitRecord {
                    scanner: hit.scanner.clone(),
                    rule: hit.rule.clone(),
                    sha256: hit.sha256.clone(),
                });
                self.recorded
                    .push((*lane, hit.start, hit.end, hit.flag_only));
            } else {
                self.report.dropped_hits += 1;
            }
        }
        verdict
    }

    fn drop_superseded(&mut self, lane: usize, hit: &WindowHit) {
        let mut i = 0;
        while i < self.recorded.len() {
            let (l, a, b, flag_only) = self.recorded[i];
            if l == lane && flag_only && a < hit.end && hit.start < b {
                self.recorded.remove(i);
                self.report.hits.remove(i);
            } else {
                i += 1;
            }
        }
    }

    fn block(&mut self, step: &mut Step) {
        self.report.verdict = Verdict::Block;
        self.held.clear();
        step.out.push(sse::blocked_event(self.protocol));
        step.ended = true;
    }

    /// Mark `hit`'s span for removal in every held field of its lane.
    fn cut(&mut self, h: &LaneHit) {
        let hit = &h.hit;
        let marker = hit.new.then(|| format!("[REDACTED:{}]", hit.scanner));
        for held in &mut self.held {
            for (i, f) in held.fields.iter().enumerate() {
                let (a, b) = (f.start, f.start + f.span.text.len());
                if f.lane == h.lane && hit.start < b && a < hit.end {
                    let first = (a..b).contains(&hit.start);
                    let local = (hit.start.max(a) - a, hit.end.min(b) - a);
                    held.cuts[i].push((local.0, local.1, marker.clone().filter(|_| first)));
                }
            }
        }
    }

    /// Can no future match reach back into `h`?
    fn safe(&self, h: &Held) -> bool {
        h.fields.iter().all(|f| {
            f.lane >= WHOLE || {
                let lane = &self.lanes[f.lane];
                let end = f.start + f.span.text.len();
                // While a match can still cross into it (AGENT-329), an
                // output's own part of it may not go.
                (lane.done || end <= lane.window.base()) && lane.bridge.is_none()
            }
        })
    }

    /// Send held events no future match can reach, oldest first.
    fn release(&mut self, step: &mut Step) {
        while let Some(front) = self.held.front() {
            let safe = self.safe(front);
            let over = self.held_bytes > self.max_held;
            if !safe && !over {
                break;
            }
            if !safe && self.on_error == OnError::FailClosed {
                self.note_error("stream events held past max_scan_bytes".into());
                return self.block(step);
            }
            self.hold_overflowed |= !safe;
            let h = self.held.pop_front().expect("front exists");
            self.held_bytes -= h.cost;
            for (f, cuts) in h.fields.iter().zip(&h.cuts).filter(|(f, _)| f.lane < WHOLE) {
                // Whitespace a match later grows over gives nothing of it
                // away, nor does text already cut, nor a field of nothing else.
                let kept = sent_end(&f.span.text, cuts);
                if kept > 0 {
                    let lane = &mut self.lanes[f.lane];
                    lane.sent = lane.sent.max(f.start + kept);
                }
            }
            step.out.push(render(&h));
        }
    }
}

/// Where `text` ends past trailing whitespace, escaped whitespace (`\n`,
/// `\\n`, `\u000a` as JSON nested in a string spells it) included.
fn content_end(text: &str) -> usize {
    let mut t = text;
    loop {
        let trimmed = t.trim_end();
        let escaped = [
            "n", "r", "t", "u0009", "u000a", "u000A", "u000d", "u000D", "u0020",
        ]
        .iter()
        .find_map(|e| trimmed.strip_suffix(e).filter(|s| s.ends_with('\\')));
        t = match escaped {
            Some(s) => s.trim_end_matches('\\'),
            None if trimmed.len() < t.len() => trimmed,
            None => return t.len(),
        };
    }
}

/// Where what a field sent ends for a match found later: past trailing
/// whitespace and past text its cuts removed (another rule's match, say).
fn sent_end(text: &str, cuts: &Cuts) -> usize {
    let mut end = content_end(text);
    if cuts.is_empty() {
        return end;
    }
    // The cuts merged into disjoint spans, walked back once: `end` only
    // falls, so a span past it is never needed again.
    let mut spans: Vec<(usize, usize)> = cuts.iter().map(|&(a, b, _)| (a, b)).collect();
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (a, b) in spans {
        match merged.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    while let Some(&(a, b)) = merged.last() {
        if a >= end {
            merged.pop();
        } else if end <= b {
            end = content_end(&text[..a]);
            merged.pop();
        } else {
            break;
        }
    }
    end
}

/// The event as it goes out: untouched unless a field has cuts.
fn render(h: &Held) -> Vec<u8> {
    if h.cuts.iter().all(Vec::is_empty) {
        return h.event.raw.clone();
    }
    let edits: Vec<(sse::Place, String)> = h
        .fields
        .iter()
        .zip(&h.cuts)
        .filter(|(_, cuts)| !cuts.is_empty())
        .map(|(f, cuts)| (f.span.place.clone(), apply_cuts(&f.span.text, cuts)))
        .collect();
    sse::rewrite(&h.event, &edits)
}

/// Remove the merged cut ranges from `text`, leaving each marker.
fn apply_cuts(text: &str, cuts: &Cuts) -> String {
    let mut sorted = cuts.clone();
    sorted.sort_by_key(|c| c.0);
    let mut merged: Cuts = Vec::new();
    for (start, end, marker) in sorted {
        match merged.last_mut() {
            Some(last) if start <= last.1 => {
                last.1 = last.1.max(end);
                if last.2.is_none() {
                    last.2 = marker;
                }
            }
            _ => merged.push((start, end, marker)),
        }
    }
    let mut out = String::new();
    let mut at = 0;
    for (start, end, marker) in merged {
        out.push_str(text.get(at..start).unwrap_or_default());
        if let Some(m) = marker {
            out.push_str(&m);
        }
        at = end;
    }
    out.push_str(text.get(at..).unwrap_or_default());
    out
}

#[cfg(test)]
mod tests {
    use super::super::{OnError, Verdict, dlp::Dlp, sse};
    use super::*;
    use std::sync::Arc;

    fn policy(on_hit: Verdict) -> DirectionPolicy {
        DirectionPolicy {
            scanners: vec![Arc::new(Dlp)],
            on_hit,
            on_error: OnError::FailOpen,
            max_scan_bytes: 1 << 20,
        }
    }

    fn key() -> String {
        // Assembled at run time: no credential-format literal in the repo.
        format!(
            "ghp_{}",
            &"Qm7Zx2Lk9Vb4Nc8Rt1Hy6Jd3Fg5Sa0Wp".repeat(2)[..36]
        )
    }

    fn q(s: &str) -> String {
        serde_json::to_string(s).unwrap()
    }

    fn chat(d: &str) -> String {
        format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{}}}}}]}}\n\n",
            q(d)
        )
    }

    fn responses(d: &str) -> String {
        format!(
            "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"delta\":{}}}\n\n",
            q(d)
        )
    }

    fn anthropic(d: &str) -> String {
        format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":{}}}}}\n\n",
            q(d)
        )
    }

    const PING: &str = "event: ping\ndata: {\"type\":\"ping\"}\n\n";
    const DONE: &str = "data: [DONE]\n\n";

    /// The key one character per event, between ordinary text.
    fn stream(event: fn(&str) -> String, tail: &str) -> Vec<String> {
        let mut out = vec![PING.to_string(), event("Here is the key: ")];
        out.extend(key().chars().map(|c| event(&c.to_string())));
        out.push(event(" and that is all."));
        out.push(tail.to_string());
        out
    }

    fn run(p: &DirectionPolicy, events: &[String]) -> (String, StreamInspector) {
        let mut i = StreamInspector::new(p);
        let mut out = Vec::new();
        for e in events {
            out.extend(i.push(e.as_bytes()).out);
        }
        out.extend(i.finish().out);
        (String::from_utf8(out.concat()).unwrap(), i)
    }

    #[test]
    fn a_streamed_pem_key_longer_than_the_overlap_is_redacted_whole() {
        let line = "QUJD".repeat(16);
        let mut text = String::from("Here: -----BEGIN PRIVATE KEY-----\n");
        for _ in 0..300 {
            text.push_str(&line);
            text.push('\n');
        }
        text.push_str("-- that is all.");
        let mut events: Vec<String> = text
            .as_bytes()
            .chunks(64)
            .map(|c| chat(std::str::from_utf8(c).unwrap()))
            .collect();
        events.push(DONE.to_string());
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(!out.contains("QUJD"), "a key line was forwarded");
        assert!(out.contains("that is all"), "{out}");
        assert!(!out.contains("inspection_blocked"), "{out}");
        assert!(!i.hold_overflowed());
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    /// AGENT-315: tool arguments are JSON in a JSON string, so a key in
    /// them can sit behind a second level of escaping that the event's own
    /// decoding leaves in place (`\u0067hp_...`). It is redacted like a
    /// plain one, even streamed a character at a time.
    #[test]
    fn a_key_behind_a_nested_escape_is_redacted() {
        let k = key();
        let args = format!("{{\"k\": \"\\u0067{}\"}}", &k[1..]);
        let mut events = vec![chat("args: ")];
        events.extend(args.chars().map(|c| chat(&c.to_string())));
        events.push(chat(" done."));
        events.push(DONE.to_string());
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(!leaked(&out), "{out}");
        assert!(out.contains("[REDACTED:dlp]"), "{out}");
        assert!(out.contains("done."), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
        let (out, i) = run(&policy(Verdict::Block), &events);
        assert!(!leaked(&out), "{out}");
        assert_eq!(i.report().verdict, Verdict::Block);
    }

    /// AGENT-315: a PEM key found only unescaped (one escaped dash in its
    /// BEGIN line) is redacted whole when streamed, like a plain one.
    #[test]
    fn a_streamed_escaped_pem_key_is_redacted_whole() {
        let line = "QUJD".repeat(16);
        let mut text = String::from(r"Here: \u002d----BEGIN PRIVATE KEY-----\n");
        for _ in 0..300 {
            text.push_str(&line);
            text.push_str(r"\n");
        }
        text.push_str("-- that is all.");
        let mut events: Vec<String> = text
            .as_bytes()
            .chunks(64)
            .map(|c| chat(std::str::from_utf8(c).unwrap()))
            .collect();
        events.push(DONE.to_string());
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(!out.contains("QUJD"), "a key line was forwarded");
        assert!(out.contains("that is all"), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    /// AGENT-273: Azure "On Your Data" streams text in a choice's
    /// `messages[].delta`, outside its `delta`; a key split across those
    /// chunks is redacted like one split across chat deltas.
    #[test]
    fn a_key_split_across_on_your_data_chunks_is_redacted() {
        // With and without the element's own `index`.
        for tag in ["", "\"index\":0,"] {
            let chunk = |d: &str| on_your_data(tag, d);
            let k = key();
            let mut events = vec![chunk("Here: ")];
            events.extend(
                k.as_bytes()
                    .chunks(4)
                    .map(|c| chunk(std::str::from_utf8(c).unwrap())),
            );
            events.push(chunk(" done."));
            events.push(DONE.to_string());
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert!(!out.contains(&k[4..20]), "{tag}: {out}");
            assert!(out.contains("[REDACTED:dlp]"), "{tag}: {out}");
            assert_eq!(i.report().verdict, Verdict::Redact);
        }
    }

    fn on_your_data(tag: &str, d: &str) -> String {
        format!(
            "data: {{\"choices\":[{{\"index\":0,\"messages\":[{{{tag}\"delta\":{{\"content\":{}}}}}]}}]}}\n\n",
            q(d)
        )
    }

    /// Under `fail_closed`, messages addressed both by index and by
    /// position could be merged by a client into one: that blocks, as
    /// for choices and tool calls.
    #[test]
    fn on_your_data_messages_by_index_and_by_position_fail_closed() {
        let events = [
            on_your_data("\"index\":0,", "Here "),
            on_your_data("", "is "),
            DONE.to_string(),
        ];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(out.contains("inspection_blocked"), "{out}");
        assert_eq!(i.report().verdict, Verdict::Block);
    }

    /// AGENT-311: a key joined onto its BEGIN line with spaces, longer
    /// than an END is looked for across, is redacted whole when streamed.
    #[test]
    fn a_streamed_space_joined_key_is_redacted_whole() {
        let words: Vec<String> = (0..200).map(|_| "QUJD".repeat(16)).collect();
        let text = format!(
            "Here: -----BEGIN RSA PRIVATE KEY----- Proc-Type: 4,ENCRYPTED \
             DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF {}",
            words.join(" ")
        );
        let mut events: Vec<String> = text
            .as_bytes()
            .chunks(64)
            .map(|c| chat(std::str::from_utf8(c).unwrap()))
            .collect();
        events.push(chat(". That is all."));
        events.push(DONE.to_string());
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(!out.contains("QUJD"), "a key word was forwarded");
        assert!(out.contains("That is all"), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    /// AGENT-273: a stream the upstream broke off or the agent left is
    /// judged for the audit, but nothing it holds is sent.
    #[test]
    fn an_abandoned_stream_sends_nothing_it_holds() {
        let mut i = StreamInspector::new(&policy(Verdict::Redact));
        let mut out = Vec::new();
        for e in stream(chat, DONE).iter().take(20) {
            out.extend(i.push(e.as_bytes()).out);
        }
        let held = i.held.len();
        assert!(held > 0, "nothing held to drop");
        let step = i.abandon();
        assert!(step.out.is_empty(), "abandon sent held events");
        assert!(step.ended);
        assert!(i.push(chat("more").as_bytes()).out.is_empty());
    }

    /// AGENT-273 (M1): the half event a disconnect leaves behind is not
    /// judged as an event, so it cannot write a false block row.
    #[test]
    fn an_abandoned_partial_event_is_not_judged() {
        let mut i = StreamInspector::new(&closed(1 << 20, Verdict::Redact));
        i.push(chat("fine").as_bytes());
        i.push(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\\nb");
        i.abandon();
        assert_eq!(i.report().verdict, Verdict::Pass, "{:?}", i.report());
        assert!(i.report().error.is_none(), "{:?}", i.report());
    }

    /// AGENT-273: an event too big to judge under `fail_open` switches the
    /// stream to passthrough, but the text already held is judged first,
    /// so a key that arrived too small to trigger a scan is still redacted.
    #[test]
    fn an_oversized_event_does_not_release_held_text_unscanned() {
        let p = DirectionPolicy {
            max_scan_bytes: 8192,
            ..policy(Verdict::Redact)
        };
        let events = vec![
            chat(&"x ".repeat(1000)),
            chat(&key()),
            chat(&"y".repeat(10_000)),
            DONE.to_string(),
        ];
        let (out, i) = run(&p, &events);
        assert!(!leaked(&out), "{out}");
        assert!(out.contains("[REDACTED:dlp]"), "{out}");
        assert_eq!(i.report().skipped, Some(super::super::SkipReason::Oversize));
        // Under block it blocks there, before anything held goes out.
        let p = DirectionPolicy {
            max_scan_bytes: 8192,
            ..policy(Verdict::Block)
        };
        let (out, i) = run(&p, &events);
        assert!(!leaked(&out), "{out}");
        assert!(out.contains("inspection_blocked"), "{out}");
        assert!(!out.contains("yyyy"), "the oversized event went out");
        assert_eq!(i.report().verdict, Verdict::Block);
    }

    #[test]
    fn split_secret_redacted_before_forwarding() {
        let k = key();
        for (event, tail) in [
            (chat as fn(&str) -> String, DONE),
            (responses, DONE),
            (anthropic, PING),
        ] {
            let (out, i) = run(&policy(Verdict::Redact), &stream(event, tail));
            assert!(!leaked(&out), "leaked part of {k} in {out}");
            assert!(out.contains("[REDACTED:dlp]"), "{out}");
            assert!(out.contains("and that is all."));
            assert_eq!(i.report().hits.len(), 1, "counted once");
            assert_eq!(i.report().verdict, Verdict::Redact);
            // Every event still parses with its JSON intact.
            let mut parser = sse::SseParser::default();
            for e in parser.push(out.as_bytes()) {
                if let Some(d) = e.data.filter(|d| d != "[DONE]") {
                    serde_json::from_str::<serde_json::Value>(&d).unwrap();
                }
            }
        }
    }

    #[test]
    fn flag_forwards_each_event_at_once() {
        let mut i = StreamInspector::new(&policy(Verdict::Flag));
        let first = chat("hello");
        assert_eq!(i.push(first.as_bytes()).out, vec![first.into_bytes()]);
        let events = stream(chat, DONE);
        let (out, i) = run(&policy(Verdict::Flag), &events);
        assert_eq!(out, events.concat(), "flag changes nothing");
        assert_eq!(i.report().verdict, Verdict::Flag);
    }

    #[test]
    fn block_ends_the_stream_with_an_error_event() {
        for (event, tail, shape) in [
            (
                chat as fn(&str) -> String,
                DONE,
                "\"code\":\"inspection_blocked\"",
            ),
            (anthropic, PING, "\"type\":\"inspection_blocked\""),
        ] {
            let events = stream(event, tail);
            let mut i = StreamInspector::new(&policy(Verdict::Block));
            let mut out = Vec::new();
            let mut ended = false;
            for e in &events {
                let step = i.push(e.as_bytes());
                assert!(!ended || step.out.is_empty(), "output after the end");
                out.extend(step.out);
                ended |= step.ended;
            }
            assert!(ended);
            let out = String::from_utf8(out.concat()).unwrap();
            assert!(
                out.ends_with("\n\n") && out.contains("event: error"),
                "{out}"
            );
            assert!(out.contains(shape), "{out}");
            assert!(!out.contains(&key()[..8]));
        }
    }

    #[test]
    fn non_text_events_pass_byte_identical() {
        let start = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\"}}\n\n";
        let events = vec![
            start.to_string(),
            PING.to_string(),
            anthropic("plain text"),
            DONE.to_string(),
        ];
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert_eq!(out, events.concat());
        assert!(i.report().hits.is_empty());
    }

    fn closed(max_scan_bytes: usize, on_hit: Verdict) -> DirectionPolicy {
        DirectionPolicy {
            on_error: OnError::FailClosed,
            max_scan_bytes,
            ..policy(on_hit)
        }
    }

    #[test]
    fn aggregate_events_are_redacted_too() {
        let k = key();
        let done = format!(
            "event: response.output_text.done\ndata: {{\"type\":\"response.output_text.done\",\"text\":{}}}\n\n",
            q(&format!("Here is the key: {k} and that is all."))
        );
        let mut events = stream(responses, DONE);
        events.insert(events.len() - 1, done);
        let (out, _) = run(&policy(Verdict::Redact), &events);
        assert!(!out.contains(&k[..12]), "{out}");
    }

    #[test]
    fn an_unbroken_event_past_the_cap_fails_closed() {
        let mut i = StreamInspector::new(&closed(1024, Verdict::Flag));
        let step = i.push(format!("data: {}", "x".repeat(5000)).as_bytes());
        assert!(step.ended);
        assert!(
            String::from_utf8(step.out.concat())
                .unwrap()
                .contains("inspection_blocked")
        );
    }

    #[test]
    fn hold_overflow_fails_closed() {
        let (out, i) = run(&closed(300, Verdict::Redact), &stream(chat, DONE));
        assert!(out.contains("inspection_blocked"), "{out}");
        assert!(!out.contains(&key()[..8]));
        assert_eq!(i.report().verdict, Verdict::Block);
    }

    #[test]
    fn an_unterminated_last_event_is_scanned() {
        let k = key();
        let mut i = StreamInspector::new(&policy(Verdict::Redact));
        let mut out = i.push(chat("start ").as_bytes()).out;
        let last = chat(&format!("key {k}"));
        out.extend(i.push(last.trim_end().as_bytes()).out);
        out.extend(i.finish().out);
        let out = String::from_utf8(out.concat()).unwrap();
        assert!(!out.contains(&k[..12]), "{out}");
        assert!(out.contains("[REDACTED:dlp]"));
    }

    /// The text a client rebuilds from `out`, one string per output.
    fn client_texts(out: &str) -> Vec<String> {
        use serde_json::Value;
        let mut lanes = std::collections::BTreeMap::<String, String>::new();
        let mut add = |k: String, t: Option<&str>| {
            if let Some(t) = t {
                lanes.entry(k).or_default().push_str(t);
            }
        };
        for e in sse::SseParser::default().push(out.as_bytes()) {
            let Some(v) = e
                .data
                .as_deref()
                .and_then(|d| serde_json::from_str::<Value>(d).ok())
            else {
                continue;
            };
            for c in v["choices"].as_array().into_iter().flatten() {
                add(format!("c{}", c["index"]), c["delta"]["content"].as_str());
                for t in c["delta"]["tool_calls"].as_array().into_iter().flatten() {
                    let k = format!("t{}.{}", c["index"], t["index"]);
                    add(k, t["function"]["arguments"].as_str());
                }
            }
            add("r".into(), v["delta"].as_str());
            add(format!("a{}", v["index"]), v["delta"]["text"].as_str());
            add("done".into(), v["text"].as_str());
        }
        lanes.into_values().collect()
    }

    /// Does any 8 characters of the key reach the agent, as sent or as a
    /// client rebuilds it?
    fn leaked(out: &str) -> bool {
        let k = key();
        let mut texts = client_texts(out);
        texts.push(out.to_string());
        texts
            .iter()
            .any(|t| (0..=k.len() - 8).any(|i| t.contains(&k[i..i + 8])))
    }

    fn chat_n(choice: usize, d: &str) -> String {
        format!(
            "data: {{\"choices\":[{{\"index\":{choice},\"delta\":{{\"content\":{}}}}}]}}\n\n",
            q(d)
        )
    }

    #[test]
    fn interleaved_choices_keep_their_own_window() {
        let k = key();
        let mut events = vec![chat_n(0, "key: "), chat_n(1, "other: ")];
        for c in k.chars() {
            events.push(chat_n(0, &c.to_string()));
            events.push(chat_n(1, "ok "));
        }
        events.push(DONE.to_string());
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(!leaked(&out), "{out}");
        assert_eq!(i.report().hits.len(), 1);
    }

    #[test]
    fn interleaved_tool_calls_are_keyed_by_their_index() {
        let call = |n: usize, a: &str| {
            format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":{n},\"function\":{{\"arguments\":{}}}}}]}}}}]}}\n\n",
                q(a)
            )
        };
        let mut events = Vec::new();
        for c in key().chars() {
            events.push(call(0, &c.to_string()));
            events.push(call(1, "{}"));
        }
        events.push(DONE.to_string());
        let (out, _) = run(&policy(Verdict::Redact), &events);
        assert!(!leaked(&out), "{out}");
    }

    /// AGENT-273: under `fail_closed` a later tool call finishes the
    /// earlier ones, so an upstream that interleaves them writes to a
    /// finished output and the stream is blocked, not leaked.
    #[test]
    fn interleaved_tool_calls_block_under_fail_closed() {
        let call = |n: usize, a: &str| {
            format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":{n},\"function\":{{\"arguments\":{}}}}}]}}}}]}}\n\n",
                q(a)
            )
        };
        let mut events = Vec::new();
        for c in key().chars() {
            events.push(call(0, &c.to_string()));
            events.push(call(1, "{}"));
        }
        events.push(DONE.to_string());
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!leaked(&out), "{out}");
        assert_eq!(
            i.report().error.as_deref(),
            Some("stream text after its output finished")
        );
    }

    fn anthropic_at(i: usize, d: &str) -> String {
        format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":{i},\"delta\":{{\"type\":\"text_delta\",\"text\":{}}}}}\n\n",
            q(d)
        )
    }

    fn anthropic_stop(i: usize) -> String {
        format!(
            "event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{i}}}\n\n"
        )
    }

    fn responses_at(c: usize, d: &str) -> String {
        format!(
            "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":{c},\"delta\":{}}}\n\n",
            q(d)
        )
    }

    fn responses_stop(c: usize) -> String {
        format!(
            "event: response.content_part.done\ndata: {{\"type\":\"response.content_part.done\",\"output_index\":0,\"content_index\":{c}}}\n\n"
        )
    }

    const MESSAGE_STOP: &str = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    const MESSAGE_START: &str =
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{}}\n\n";
    const COMPLETED: &str =
        "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n";

    type At = fn(usize, &str) -> String;
    type Stop = fn(usize) -> String;
    const JOINED: [(At, Stop, &str); 2] = [
        (anthropic_at, anthropic_stop, MESSAGE_STOP),
        (responses_at, responses_stop, COMPLETED),
    ];

    /// A key whose last character opens the next output: the first output
    /// is finished before the key is complete.
    fn split_across(at: At, stop: Stop, end: &str) -> Vec<String> {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        let mut events = vec![at(0, "Here is the key: ")];
        events.extend(head.chars().map(|c| at(0, &c.to_string())));
        events.push(stop(0));
        events.push(at(1, last));
        events.push(at(1, " and that is all."));
        events.push(stop(1));
        events.push(end.to_string());
        events
    }

    /// A key split across a join was found and the stream blocked before
    /// its rest went out: its start had gone with the earlier output, so
    /// a redaction could not remove it whole.
    fn assert_split_blocked(out: &str, i: &StreamInspector) {
        let text = client_texts(out).concat();
        assert!(!text.contains(&key()), "{text}");
        assert!(!text.contains("that is all"), "the rest went out: {text}");
        assert_eq!(i.report().verdict, Verdict::Block, "{out}");
        assert!(i.report().redaction_incomplete);
        assert!(i.report().hits.iter().any(|h| h.rule != "entropy"));
    }

    /// AGENT-329: clients join an Anthropic message's text blocks, and the
    /// Responses SDK's `output_text` joins content parts, so a key split
    /// between two such outputs reaches the agent whole unless the second
    /// output's window starts with the first one's tail.
    #[test]
    fn a_key_split_across_joined_outputs_is_caught() {
        for (at, stop, end) in JOINED {
            let events = split_across(at, stop, end);
            for p in [policy(Verdict::Redact), closed(1 << 20, Verdict::Redact)] {
                let (out, i) = run(&p, &events);
                assert_split_blocked(&out, &i);
            }
            let (out, i) = run(&policy(Verdict::Block), &events);
            assert!(!client_texts(&out).concat().contains(&key()), "{out}");
            assert_eq!(i.report().verdict, Verdict::Block);
            assert!(!i.report().redaction_incomplete);
        }
    }

    /// The carried tail only joins a match: honest outputs pass untouched.
    #[test]
    fn joined_outputs_without_a_key_pass_untouched() {
        for (at, stop, end) in JOINED {
            let events = vec![
                at(0, "Here is the plan: "),
                stop(0),
                at(1, "first, read the file."),
                stop(1),
                end.to_string(),
            ];
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert_eq!(out, events.concat());
            assert_eq!(i.report().hits, Vec::new());
        }
    }

    /// A new output of a join group starts from the group's open one, which
    /// keeps its window: a key split between two outputs an upstream
    /// interleaves is still caught, and a write back to the earlier output
    /// joins nothing a client joins, so `fail_closed` blocks it.
    #[test]
    fn interleaved_joined_outputs_start_from_the_open_one() {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        for (at, stop, end) in JOINED {
            let events = vec![
                at(0, head),
                at(1, last),
                at(1, " and that is all."),
                stop(1),
                end.to_string(),
            ];
            let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert_split_blocked(&out, &i);
            assert_eq!(i.report().error, None);

            let back = vec![
                at(0, "Here: "),
                at(1, "more"),
                at(0, "again"),
                end.to_string(),
            ];
            let (_, i) = run(&closed(1 << 20, Verdict::Redact), &back);
            assert_eq!(
                i.report().error.as_deref(),
                Some("joined stream outputs interleaved")
            );
            let (out, i) = run(&policy(Verdict::Redact), &back);
            assert_eq!(out, back.concat());
            assert!(i.hold_overflowed());
        }
    }

    /// The joined scan is added to each output's own, not put in its place:
    /// a whole key at a block's start, right after a word that ended the
    /// previous block, is still at a word boundary in its own output.
    #[test]
    fn a_key_after_a_word_in_the_previous_output_is_still_caught() {
        for (at, stop, end) in JOINED {
            for on_hit in [Verdict::Redact, Verdict::Block] {
                let events = vec![
                    at(0, "hello"),
                    stop(0),
                    at(1, &format!("{} and that is all.", key())),
                    stop(1),
                    end.to_string(),
                ];
                let (out, i) = run(&policy(on_hit), &events);
                assert!(!leaked(&out), "{on_hit:?}: {out}");
                assert_eq!(i.report().verdict, on_hit);
            }
        }
    }

    /// A streaming scanner that finds nothing and counts the bytes it is
    /// given, with a long match so a whole output is carried.
    struct Counting(Arc<std::sync::atomic::AtomicUsize>);
    impl Scanner for Counting {
        fn id(&self) -> &str {
            "counting"
        }
        fn max_match_len(&self) -> usize {
            1 << 16
        }
        fn scan(
            &self,
            text: &str,
            _: Direction,
        ) -> Result<Vec<super::super::Hit>, super::super::ScanError> {
            self.0
                .fetch_add(text.len(), std::sync::atomic::Ordering::Relaxed);
            Ok(Vec::new())
        }
    }

    /// A PEM key whose BEGIN line ends one output and whose lines fill the
    /// next, past what that output's own window keeps: only the bridge
    /// sees the whole key, and nothing of it goes before the bridge does.
    #[test]
    fn a_pem_key_begun_in_one_output_is_cut_whole_in_the_next() {
        let line = "QUJD".repeat(16);
        for (at, stop, end) in JOINED {
            let mut events = vec![at(0, "Here: -----BEGIN PRIVATE KEY-----\n"), stop(0)];
            for _ in 0..300 {
                events.push(at(1, &format!("{line}\n")));
            }
            events.push(at(1, "-- that is all."));
            events.push(stop(1));
            events.push(end.to_string());
            let (out, i) = run(&policy(Verdict::Redact), &events);
            let text = client_texts(&out).concat();
            assert!(!text.contains("QUJD"), "a key line was forwarded");
            assert!(text.contains("that is all"), "{text}");
            assert_eq!(i.report().verdict, Verdict::Redact);
        }
    }

    /// A short text block, then a large tool input: the text's tail goes
    /// when the tool call starts, so the input does not queue behind it
    /// and pass the held limit.
    #[test]
    fn a_tool_call_after_a_text_block_ends_its_join() {
        use serde_json::json;
        let mut events = vec![
            anthropic_at(0, "I'll write the file now."),
            anthropic_stop(0),
        ];
        events.push(ev(
            "content_block_start",
            json!({"index": 1, "content_block": {"type": "tool_use", "id": "t1", "name": "write", "input": {}}}),
        ));
        for _ in 0..8000 {
            events.push(ev(
                "content_block_delta",
                json!({"index": 1, "delta": {"type": "input_json_delta", "partial_json": "abcdefghij klmnopqrst uvwxyz0123 4567"}}),
            ));
        }
        events.push(anthropic_stop(1));
        events.push(MESSAGE_STOP.to_string());
        for p in [closed(1 << 20, Verdict::Redact), policy(Verdict::Redact)] {
            let mut i = StreamInspector::new(&p);
            let mut out = String::new();
            for e in &events[..4] {
                out.push_str(&String::from_utf8(i.push(e.as_bytes()).out.concat()).unwrap());
            }
            assert!(out.contains("write the file"), "held behind the tool call");
            for e in &events[4..] {
                i.push(e.as_bytes());
            }
            i.finish();
            assert_eq!(i.report().error, None);
            assert!(!i.hold_overflowed());
        }
    }

    /// Responses sends each part's whole text again when it is done, where
    /// no cut of the deltas reaches: the stream stops before the second
    /// part's copies go, so the agent never gets the whole key.
    #[test]
    fn a_split_key_in_responses_done_copies_is_not_sent_whole() {
        let k = key();
        let (head, last) = k.split_at(20);
        let done = |c: usize, text: &str| {
            format!(
                "event: response.output_text.done\ndata: {{\"type\":\"response.output_text.done\",\"output_index\":0,\"content_index\":{c},\"text\":{}}}\n\n",
                q(text)
            )
        };
        let events = vec![
            responses_at(0, head),
            done(0, head),
            responses_stop(0),
            responses_at(1, last),
            responses_at(1, " and that is all."),
            done(1, &format!("{last} and that is all.")),
            responses_stop(1),
            COMPLETED.to_string(),
        ];
        for p in [policy(Verdict::Redact), closed(1 << 20, Verdict::Redact)] {
            let (out, i) = run(&p, &events);
            assert!(!out.contains(last), "{out}");
            assert_split_blocked(&out, &i);
        }
    }

    /// A key across three outputs, the middle one shorter than the key:
    /// the middle one passes on the bridge's tail, not just its own text.
    #[test]
    fn a_key_across_a_short_middle_output_is_caught() {
        let k = key();
        for (at, stop, end) in JOINED {
            let events = vec![
                at(0, &format!("Here: {}", &k[..20])),
                stop(0),
                at(1, &k[20..21]),
                stop(1),
                at(2, &format!("{} and that is all.", &k[21..])),
                stop(2),
                end.to_string(),
            ];
            for p in [policy(Verdict::Redact), closed(1 << 20, Verdict::Redact)] {
                let (out, i) = run(&p, &events);
                assert_split_blocked(&out, &i);
            }
        }
    }

    /// Clients join a group's outputs by index: an output starting below
    /// an earlier one is out of order, not joined after it.
    #[test]
    fn joined_outputs_out_of_order_are_not_joined() {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        for (at, stop, end) in JOINED {
            let events = vec![at(1, head), stop(1), at(0, last), stop(0), end.to_string()];
            let (_, i) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert_eq!(
                i.report().error.as_deref(),
                Some("joined stream outputs out of order")
            );
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert_eq!(out, events.concat());
            assert!(i.hold_overflowed());
        }
    }

    /// An out-of-order output starting while the earlier one is open takes
    /// no tail from it: the client joins them the other way round.
    #[test]
    fn an_out_of_order_output_takes_no_tail_from_an_open_one() {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        for (at, stop, end) in JOINED {
            let events = vec![at(1, head), at(0, last), stop(0), stop(1), end.to_string()];
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert_eq!(out, events.concat());
            assert!(i.hold_overflowed());
            assert_ne!(i.report().verdict, Verdict::Block, "{:?}", i.report().hits);
        }
    }

    /// An out-of-order output lends no tail when it finishes either: the
    /// next output follows the group's latest, not it.
    #[test]
    fn an_out_of_order_output_lends_no_tail_when_it_finishes() {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        for (at, stop, end) in JOINED {
            let events = vec![
                at(1, " middle "),
                stop(1),
                at(0, head),
                stop(0),
                at(2, last),
                stop(2),
                end.to_string(),
            ];
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert_eq!(out, events.concat());
            assert!(i.hold_overflowed());
            assert_ne!(i.report().verdict, Verdict::Block, "{:?}", i.report().hits);
        }
    }

    /// The same with the out-of-order output still open when the next one
    /// starts: it isn't the group's latest, so it lends no tail (AGENT-328).
    #[test]
    fn an_open_out_of_order_output_lends_no_tail_when_the_next_starts() {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        for (at, stop, end) in JOINED {
            let events = vec![
                at(1, " middle "),
                stop(1),
                at(0, head),
                at(2, last),
                stop(0),
                stop(2),
                end.to_string(),
            ];
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert_eq!(out, events.concat());
            assert!(i.hold_overflowed());
            assert_ne!(i.report().verdict, Verdict::Block, "{:?}", i.report().hits);
        }
    }

    /// The group's latest output, reopened after an out-of-order one
    /// superseded it, still lends its tail to the next: clients join 1 then
    /// 2, so a key split there is caught and the stream blocked rather than
    /// the key's end sent to complete it (AGENT-328).
    #[test]
    fn a_reopened_latest_output_lends_its_tail_to_the_next() {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        for (at, stop, end) in JOINED {
            let events = vec![
                at(1, "x "),
                at(0, "y "),
                at(1, head),
                at(2, last),
                stop(0),
                stop(1),
                stop(2),
                end.to_string(),
            ];
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert_split_blocked(&out, &i);
            assert!(i.hold_overflowed());
        }
    }

    /// An out-of-order output starting between the group's latest one and
    /// the next takes nothing from either: the latest, still open or
    /// finished, lends its tail to the next all the same (AGENT-328).
    #[test]
    fn an_out_of_order_output_between_two_joined_ones_keeps_their_join() {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        for (at, stop, end) in JOINED {
            for finished in [false, true] {
                let mut events = vec![at(1, &format!("x {head}"))];
                if finished {
                    events.push(stop(1));
                }
                events.extend([at(0, "y "), at(2, last), at(2, " and that is all.")]);
                events.extend([stop(0), stop(2)]);
                if !finished {
                    events.push(stop(1));
                }
                events.push(end.to_string());
                let (out, i) = run(&policy(Verdict::Redact), &events);
                assert_split_blocked(&out, &i);
                assert!(i.hold_overflowed());
            }
        }
    }

    /// A split that blocks still audits the other hits found with it.
    #[test]
    fn a_split_block_records_the_hits_found_with_it() {
        let k = key();
        let other = format!(
            "ghp_{}",
            &"Zx2Lk9Vb4Nc8Rt1Hy6Jd3Fg5Sa0WpQm7".repeat(2)[..36]
        );
        let (head, last) = k.split_at(k.len() - 1);
        for (at, stop, end) in JOINED {
            let events = vec![
                at(0, &format!("Here: {head}")),
                stop(0),
                at(1, &format!("{last} and {other}")),
                stop(1),
                end.to_string(),
            ];
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert_eq!(i.report().verdict, Verdict::Block, "{out}");
            assert!(i.report().redaction_incomplete);
            let named = i
                .report()
                .hits
                .iter()
                .filter(|h| h.rule != "entropy")
                .count();
            assert_eq!(named, 2, "{:?}", i.report().hits);
        }
    }

    /// Text after a key's last part, sent a byte at a time in the joined
    /// output, does not release that part before the bridge scans it.
    #[test]
    fn a_batched_bridge_holds_the_key_until_it_scans() {
        for (at, stop, end) in JOINED {
            let mut events = split_across(at, stop, end);
            let tail = events.split_off(events.len() - 2);
            events.extend("x".repeat(400).chars().map(|c| at(1, &c.to_string())));
            events.extend(tail);
            for p in [policy(Verdict::Redact), closed(1 << 20, Verdict::Redact)] {
                let (out, i) = run(&p, &events);
                assert_split_blocked(&out, &i);
            }
        }
    }

    /// A long carried tail and a joined output sent a byte at a time: the
    /// bridge batches its scans as an output's own window does, rather
    /// than rescanning the tail on every delta.
    #[test]
    fn a_long_carried_tail_is_not_rescanned_per_delta() {
        for (at, stop, end) in JOINED {
            let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let p = DirectionPolicy {
                scanners: vec![Arc::new(Counting(count.clone()))],
                ..policy(Verdict::Redact)
            };
            let mut events = vec![at(0, &" ".repeat(50_000)), stop(0)];
            events.extend((0..1000).map(|_| at(1, "x")));
            events.push(stop(1));
            events.push(end.to_string());
            let (out, _) = run(&p, &events);
            assert_eq!(out, events.concat());
            let scanned = count.load(std::sync::atomic::Ordering::Relaxed);
            assert!(scanned < 1_000_000, "{scanned} bytes scanned");
        }
    }

    /// The tail an open output gives the next one includes text it has not
    /// scanned yet; the key is caught once.
    #[test]
    fn an_open_output_gives_its_unscanned_text_too() {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        for (at, _, end) in JOINED {
            let mut events = vec![at(0, "Here: ")];
            events.extend(head.chars().map(|c| at(0, &c.to_string())));
            events.push(at(1, last));
            events.push(at(1, " and that is all."));
            events.push(end.to_string());
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert_split_blocked(&out, &i);
            let named = i
                .report()
                .hits
                .iter()
                .filter(|h| h.rule != "entropy")
                .count();
            assert_eq!(named, 1, "{:?}", i.report().hits);
        }
    }

    /// Tool arguments are not joined: interleaved Responses function calls
    /// keep their own windows, so a key split within one call is redacted
    /// as before, and honest interleaving is not blocked.
    #[test]
    fn interleaved_function_calls_are_not_joined() {
        let args = |o: usize, d: &str| {
            format!(
                "event: response.function_call_arguments.delta\ndata: {{\"type\":\"response.function_call_arguments.delta\",\"output_index\":{o},\"delta\":{}}}\n\n",
                q(d)
            )
        };
        let k = key();
        let (a, b) = k.split_at(20);
        let events = vec![args(0, a), args(1, "{}"), args(0, b), COMPLETED.to_string()];
        for p in [policy(Verdict::Redact), closed(1 << 20, Verdict::Redact)] {
            let (out, i) = run(&p, &events);
            assert!(!client_texts(&out).concat().contains(&k), "{out}");
            assert_eq!(i.report().verdict, Verdict::Redact);
            assert!(i.carry.is_empty());
        }
    }

    /// Only the allow-listed groups carry a tail: outputs under keys an
    /// upstream invents keep nothing after they finish.
    #[test]
    fn invented_outputs_carry_nothing() {
        let mut events = vec![MESSAGE_START.to_string()];
        for n in 0..50 {
            events.push(format!(
                "event: x\ndata: {{\"type\":\"x\",\"index\":{n},\"p{n}\":{}}}\n\n",
                q(&format!("a{}", " ".repeat(2000)))
            ));
            events.push(anthropic_stop(n));
        }
        let (_, i) = run(&closed(1 << 16, Verdict::Redact), &events);
        assert!(i.carry.is_empty());
    }

    /// A carried tail is held text: it counts toward `max_scan_bytes`.
    #[test]
    fn carried_tails_count_toward_the_held_limit() {
        // Under `flag` nothing is held, so only the text limit applies: a
        // 3000-byte blank tail carried into the next text block's bridge,
        // which holds it with that block's 1500 bytes, as the block does.
        let events = vec![
            anthropic_at(0, &format!("x{}", " ".repeat(3000))),
            anthropic_stop(0),
            anthropic_at(1, &format!("y{}", " ".repeat(1500))),
        ];
        let (_, i) = run(&closed(4096, Verdict::Flag), &events);
        assert_eq!(
            i.report().error.as_deref(),
            Some("stream text held past max_scan_bytes")
        );
    }

    /// A match the first output reported, grown by the next output's text,
    /// is the same match: counted once.
    #[test]
    fn a_match_grown_across_a_join_is_counted_once() {
        for (at, stop, end) in JOINED {
            let events = vec![
                at(0, &format!("key {}", key())),
                stop(0),
                at(1, "abc def"),
                stop(1),
                end.to_string(),
            ];
            let (out, i) = run(&policy(Verdict::Redact), &events);
            assert_eq!(i.report().hits.len(), 1, "{:?}", i.report().hits);
            assert_eq!(client_texts(&out).concat().matches("[REDACTED").count(), 1);
        }
    }

    /// AGENT-316: under `fail_closed`, a write to a finished output gains a
    /// hostile upstream nothing over ending the stream at the close. The
    /// close judges the output's tail exactly as the stream's end would,
    /// and the later write is blocked, so the client gets the truncated
    /// stream's bytes plus the block event, and no more. A key prefix
    /// shorter than any rule's match goes out either way, as it would in a
    /// buffered scan of the truncated text.
    #[test]
    fn a_write_after_close_gains_nothing_over_ending_at_the_close() {
        let k = key();
        let (head, last) = k.split_at(k.len() - 1);
        let chat_stop =
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n";
        let block_stop =
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n";
        for (event, stop) in [
            (chat as fn(&str) -> String, chat_stop),
            (anthropic, block_stop),
        ] {
            let mut truncated = vec![PING.to_string(), event("Here is the key: ")];
            truncated.extend(head.chars().map(|c| event(&c.to_string())));
            truncated.push(stop.to_string());
            let mut attack = truncated.clone();
            attack.push(event(last));
            attack.push(event(" and that is all."));
            let policy = closed(1 << 20, Verdict::Block);
            let (cut, _) = run(&policy, &truncated);
            let (out, i) = run(&policy, &attack);
            let rest = out
                .strip_prefix(cut.as_str())
                .unwrap_or_else(|| panic!("the attack sent more than the truncated stream: {out}"));
            assert_eq!(rest.as_bytes(), sse::blocked_event(i.protocol), "{rest}");
            assert_eq!(
                i.report().error.as_deref(),
                Some("stream text after its output finished")
            );
        }
    }

    /// Nothing is held under `flag`, so interleaved tool calls are not
    /// treated as finished and the stream is not blocked.
    #[test]
    fn interleaved_tool_calls_pass_under_flag_and_fail_closed() {
        let call = |n: usize| {
            format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":{n},\"function\":{{\"arguments\":\"{{}}\"}}}}]}}}}]}}\n\n"
            )
        };
        let events = vec![call(0), call(1), call(0), DONE.to_string()];
        let (out, i) = run(&closed(1 << 20, Verdict::Flag), &events);
        assert_eq!(i.report().error, None);
        assert_eq!(out, events.concat());
    }

    /// AGENT-317: a tool call first seen below a higher-numbered one, or
    /// with a negative index, opens a fresh lane, so a key split between
    /// it and the call before is never contiguous in any window. A client
    /// merging calls by position rebuilds it, so under `fail_closed` the
    /// stream is blocked.
    #[test]
    fn a_tool_call_out_of_order_blocks_under_fail_closed() {
        let call = |n: i64, a: &str| {
            format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":{n},\"function\":{{\"arguments\":{}}}}}]}}}}]}}\n\n",
                q(a)
            )
        };
        let k = key();
        for (first, second) in [(2, 1), (0, -1), (-1, 0)] {
            // A negative first call is refused at once, before any later one.
            let mut events = if first < 0 {
                vec![]
            } else {
                vec![call(0, "{}")]
            };
            events.push(call(first, &k[..20]));
            events.push(call(second, &k[20..]));
            events.push(DONE.to_string());
            let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert!(!out.contains(&k[..20]), "{first},{second}: {out}");
            assert_eq!(
                i.report().error.as_deref(),
                Some("stream tool call out of order"),
                "{first},{second}"
            );
        }
        // In order, the same calls pass.
        let events = vec![
            call(0, "{}"),
            call(1, "{}"),
            call(2, "{}"),
            DONE.to_string(),
        ];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert_eq!(i.report().error, None);
        assert_eq!(out, events.concat());
    }

    /// AGENT-317: an output with no `index` among indexed ones gets a
    /// positional lane a client could merge into another, so under
    /// `fail_closed` the stream is blocked. All positional passes.
    #[test]
    fn mixed_indexed_and_positional_outputs_block_under_fail_closed() {
        let k = key();
        let call = |index: &str, a: &str| {
            format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{{index}\"function\":{{\"arguments\":{}}}}}]}}}}]}}\n\n",
                q(a)
            )
        };
        let content = |index: &str, a: &str| {
            format!(
                "data: {{\"choices\":[{{{index}\"delta\":{{\"content\":{}}}}}]}}\n\n",
                q(a)
            )
        };
        for events in [
            vec![call("\"index\":0,", &k[..20]), call("", &k[20..])],
            vec![call("", &k[..20]), call("\"index\":0,", &k[20..])],
            vec![content("\"index\":0,", &k[..20]), content("", &k[20..])],
        ] {
            let mut events = events;
            events.push(DONE.to_string());
            let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert!(!out.contains(&k[..20]), "{out}");
            assert_eq!(
                i.report().error.as_deref(),
                Some("stream outputs addressed both by index and by position")
            );
        }
        let events = vec![call("", "{}"), call("", "{}"), DONE.to_string()];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert_eq!(i.report().error, None);
        assert_eq!(out, events.concat());
    }

    /// AGENT-317: with no index anywhere, an element past the first of
    /// its array gets a lane of its own while a client that merges
    /// index-less entries into one slot joins it to the others, so under
    /// `fail_closed` the stream is blocked. One element per chunk passes.
    #[test]
    fn a_second_index_less_output_blocks_under_fail_closed() {
        let k = key();
        let calls = |args: &[&str]| {
            let list: Vec<String> = args
                .iter()
                .map(|a| format!("{{\"function\":{{\"arguments\":{}}}}}", q(a)))
                .collect();
            format!(
                "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{}]}}}}]}}\n\n",
                list.join(",")
            )
        };
        let events = vec![
            calls(&["{}", &k[..20]]),
            calls(&[&k[20..]]),
            DONE.to_string(),
        ];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!out.contains(&k[..20]), "{out}");
        assert_eq!(
            i.report().error.as_deref(),
            Some("stream outputs addressed only by position")
        );
        let events = vec![calls(&["{}"]), calls(&["{}"]), DONE.to_string()];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert_eq!(i.report().error, None);
        assert_eq!(out, events.concat());
    }

    /// AGENT-317: one client reads `"1.0"` as call 1, another keys it
    /// apart, and integers past 2^53 collide in JavaScript, so no lane
    /// fits every reader. Under `fail_closed` a loose index blocks.
    #[test]
    fn a_loose_index_blocks_under_fail_closed() {
        let k = key();
        let call = |index: &str, a: &str| {
            format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":{index},\"function\":{{\"arguments\":{}}}}}]}}}}]}}\n\n",
                q(a)
            )
        };
        for loose in ["\"1.0\"", "\"1\"", "1.0", "1e0", "9007199254740993"] {
            let events = vec![
                call("1", &k[..20]),
                call(loose, ", "),
                call("1", &k[20..]),
                DONE.to_string(),
            ];
            let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert!(!out.contains(&k[..20]), "{loose}: {out}");
            assert_eq!(
                i.report().error.as_deref(),
                Some("stream output index is not a plain integer"),
                "{loose}"
            );
        }
        let anthropic = ev(
            "content_block_delta",
            serde_json::json!({"index": "1.0",
            "delta": {"type": "text_delta", "text": "x"}}),
        );
        let responses = ev(
            "response.output_text.delta",
            serde_json::json!({"type": "response.output_text.delta",
            "output_index": "0.0", "content_index": 0, "delta": "x"}),
        );
        for event in [anthropic, responses] {
            let (_, i) = run(&closed(1 << 20, Verdict::Redact), &[event]);
            assert_eq!(
                i.report().error.as_deref(),
                Some("stream output index is not a plain integer")
            );
        }
    }

    /// AGENT-319: an array element anywhere in an event takes its lane
    /// from its `index`, so a loose one splits a value there as well
    /// (OpenRouter `reasoning_details`, a generic `items` array).
    #[test]
    fn a_loose_nested_index_blocks_under_fail_closed() {
        let k = key();
        let detail = |index: &str, a: &str| {
            format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_details\":[{{\"index\":{index},\"text\":{}}}]}}}}]}}\n\n",
                q(a)
            )
        };
        let item = |index: &str, a: &str| {
            format!(
                "data: {{\"items\":[{{\"index\":{index},\"text\":{}}}]}}\n\n",
                q(a)
            )
        };
        for shape in [detail, item] {
            for loose in ["\"1\"", "1.0", "null"] {
                let events = vec![
                    shape("1", &k[..20]),
                    shape(loose, ", "),
                    shape("1", &k[20..]),
                    DONE.to_string(),
                ];
                let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
                assert!(!out.contains(&k[..20]), "{loose}: {out}");
                assert_eq!(
                    i.report().error.as_deref(),
                    Some("stream output index is not a plain integer"),
                    "{loose}"
                );
            }
        }
    }

    /// AGENT-319: a top-level field no client reads as an index (a
    /// generic event's `index`, a chat chunk's) does not block.
    #[test]
    fn an_unread_top_level_index_passes_under_fail_closed() {
        let generic = "data: {\"index\":\"abc\",\"text\":\"hello\"}\n\n".to_string();
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &[generic]);
        assert!(out.contains("hello"), "{out}");
        assert_eq!(i.report().error, None);
    }

    /// AGENT-319: 2^53 is the last index every client reads exactly.
    #[test]
    fn an_index_at_two_to_the_53_is_plain() {
        let at = |n: u64| {
            format!("data: {{\"choices\":[{{\"index\":{n},\"delta\":{{\"content\":\"x\"}}}}]}}\n\n")
        };
        let (_, i) = run(&closed(1 << 20, Verdict::Redact), &[at(1 << 53)]);
        assert_eq!(i.report().error, None);
        let (_, i) = run(&closed(1 << 20, Verdict::Redact), &[at((1 << 53) + 1)]);
        assert_eq!(
            i.report().error.as_deref(),
            Some("stream output index is not a plain integer")
        );
    }

    /// AGENT-273: outputs are remembered after they finish, up to
    /// `MAX_OUTPUTS`. Past that, a new output would share a window, so
    /// `fail_closed` blocks and `fail_open` goes on, audited.
    #[test]
    fn outputs_past_the_limit_block_or_share_a_window() {
        let events: Vec<String> = (0..MAX_OUTPUTS)
            .map(|n| {
                format!(
                    "data: {{\"choices\":[{{\"index\":{n},\"delta\":{{\"content\":\"x\"}},\"finish_reason\":\"stop\"}}]}}\n\n"
                )
            })
            .collect();
        let (_, i) = run(
            &closed(1 << 20, Verdict::Redact),
            &events[..MAX_OUTPUTS - 2],
        );
        assert_eq!(i.report().error, None);
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(out.contains("inspection_blocked"), "{out}");
        assert_eq!(
            i.report().error.as_deref(),
            Some("more stream outputs than can be inspected")
        );
        let (_, i) = run(&policy(Verdict::Redact), &events);
        assert_eq!(i.report().error, None);
        assert!(i.hold_overflowed());
    }

    /// Padding beside each piece of a match (chat `obfuscation`,
    /// `service_tier`) is not in the piece's window, so it does not split
    /// the match (AGENT-265). It guards per-output windows: these fields
    /// sit outside the choice and are scanned per chunk either way.
    #[test]
    fn padding_fields_do_not_split_a_match() {
        let mut events = Vec::new();
        for (n, c) in key().chars().enumerate() {
            events.push(format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{}}}}}],\"obfuscation\":\"pad{n}x\",\"service_tier\":\"default\"}}\n\n",
                q(&c.to_string())
            ));
        }
        events.push(DONE.to_string());
        let (out, _) = run(&policy(Verdict::Redact), &events);
        assert!(!leaked(&out), "{out}");
    }

    fn gemini(text: &str) -> String {
        format!(
            "data: {{\"candidates\":[{{\"content\":{{\"parts\":[{{\"text\":{}}}],\"role\":\"model\"}},\"index\":0}}],\"usageMetadata\":{{\"promptTokenCount\":8,\"totalTokenCount\":8,\"promptTokensDetails\":[{{\"modality\":\"TEXT\",\"tokenCount\":8}}]}},\"modelVersion\":\"gemini-2.5-pro\",\"responseId\":\"r-1\"}}\n\n",
            q(text)
        )
    }

    /// A Gemini chunk whose part also carries a thought signature, as a
    /// thinking model's first chunk can.
    fn gemini_signed(text: &str) -> String {
        gemini(text).replace(
            "\"text\":",
            &format!("\"thoughtSignature\":{},\"text\":", q(&"Cg".repeat(200))),
        )
    }

    /// The first event released before the end of a stream of short
    /// text chunks.
    fn first_release(first: fn(&str) -> String, chunk: fn(&str) -> String) -> Option<usize> {
        let mut i = StreamInspector::new(&closed(1 << 20, Verdict::Redact));
        let at = (0..3000).position(|n| {
            let event = if n == 0 { first } else { chunk };
            !i.push(event(&format!("word{n:04} ")).as_bytes())
                .out
                .is_empty()
        });
        assert_ne!(i.report().verdict, Verdict::Block, "{:?}", i.report().error);
        at
    }

    /// AGENT-273: metadata repeated in every chunk comes whole in each
    /// event, so a Gemini stream's `role`, `modelVersion` or
    /// `usageMetadata`, or a thought signature, doesn't hold it longer
    /// than its text alone would, as a chat stream is.
    #[test]
    fn a_gemini_stream_is_held_no_longer_than_its_text_needs() {
        let chat = |text: &str| {
            format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{}}}}}]}}\n\n",
                q(text)
            )
        };
        let chat = first_release(chat, chat);
        assert!(chat.is_some(), "a chat stream is released as it goes");
        assert_eq!(first_release(gemini, gemini), chat);
        assert_eq!(first_release(gemini_signed, gemini), chat);
    }

    /// AGENT-321: a client joins every text part of a candidate in order
    /// (`chunk.text`), so a key split across parts, in one chunk or from
    /// one chunk's later part to the next chunk's first, is redacted.
    #[test]
    fn a_key_split_across_gemini_parts_is_redacted() {
        let k = key();
        let parts = |texts: &[&str]| {
            let parts: Vec<_> = texts
                .iter()
                .map(|t| serde_json::json!({"text": t}))
                .collect();
            format!(
                "data: {}\n\n",
                serde_json::json!({"candidates": [{"content": {"parts": parts, "role": "model"}, "index": 0}]})
            )
        };
        let (a, b) = (&k[..20], &k[20..]);
        for events in [
            vec![parts(&["here: ", a]), parts(&[b])],
            vec![parts(&[&format!("here: {a}"), b])],
        ] {
            let (out, _) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert!(!out.contains(a), "{out}");
            assert!(!out.contains(b), "{out}");
        }
    }

    /// A Gemini chunk from candidates given as JSON values.
    fn gemini_chunk(candidates: serde_json::Value) -> String {
        format!(
            "data: {}\n\n",
            serde_json::json!({ "candidates": candidates })
        )
    }

    /// AGENT-322: clients read a Gemini candidate by its position
    /// (`candidates[0]`), not its `index`, so varying or dropping `index`
    /// cannot split a key across windows.
    #[test]
    fn a_gemini_candidate_is_windowed_by_position() {
        use serde_json::json;
        let k = key();
        let (a, b) = (&k[..20], &k[20..]);
        let text = |t: &str| json!({"parts": [{"text": t}], "role": "model"});
        for (first, second) in [
            (json!({"index": 0}), json!({"index": 1})),
            (json!({}), json!({"index": 0})),
        ] {
            let mut x = first.clone();
            x["content"] = text(&format!("here: {a}"));
            let mut y = second.clone();
            y["content"] = text(b);
            let events = vec![gemini_chunk(json!([x])), gemini_chunk(json!([y]))];
            let (out, _) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert!(
                !out.contains(a) && !out.contains(b),
                "{first} {second}: {out}"
            );
        }
    }

    /// AGENT-322: clients leave a thought part out of the answer's text
    /// (`chunk.text`), so one between two halves of a key cannot hide it.
    #[test]
    fn a_thought_part_does_not_hide_a_split_answer() {
        use serde_json::json;
        let k = key();
        let (a, b) = (&k[..20], &k[20..]);
        let candidate =
            |parts: serde_json::Value| json!([{"content": {"parts": parts}, "index": 0}]);
        let thought = json!({"text": " ... ", "thought": true});
        for events in [
            vec![
                gemini_chunk(candidate(json!([{"text": format!("here: {a}")}]))),
                gemini_chunk(candidate(json!([thought]))),
                gemini_chunk(candidate(json!([{"text": b}]))),
            ],
            vec![gemini_chunk(candidate(
                json!([{"text": format!("here: {a}")}, thought, {"text": b}]),
            ))],
        ] {
            let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert!(!out.contains(a) && !out.contains(b), "{out}");
            assert_eq!(
                i.report().error.as_deref(),
                Some("stream Gemini thought after its answer")
            );
        }
    }

    /// A client that prints thought parts inline joins them with the
    /// answer, so a key running through a thought part is redacted too.
    #[test]
    fn a_key_through_a_gemini_thought_part_is_redacted() {
        use serde_json::json;
        let k = key();
        let (a, m, b) = (&k[..14], &k[14..28], &k[28..]);
        let candidate =
            |parts: serde_json::Value| json!([{"content": {"parts": parts}, "index": 0}]);
        let events = vec![
            gemini_chunk(candidate(json!([{"text": format!("here: {a}")}]))),
            gemini_chunk(candidate(json!([{"text": m, "thought": true}]))),
            gemini_chunk(candidate(json!([{"text": b}]))),
        ];
        let (out, _) = run(&policy(Verdict::Redact), &events);
        assert!(
            !out.contains(a) && !out.contains(m) && !out.contains(b),
            "{out}"
        );
    }

    /// AGENT-322: top-level indexes name nothing in a Gemini chunk, even
    /// after another protocol's event fixed the stream's scheme.
    #[test]
    fn top_level_indexes_do_not_split_gemini_text() {
        let k = key();
        let ping = "event: ping\ndata: {\"type\":\"ping\"}\n\n".to_string();
        let tagged = |n: u8, t: &str| gemini(t).replacen("{", &format!("{{\"index\":{n},"), 1);
        let events = vec![
            ping,
            tagged(0, &format!("here: {}", &k[..20])),
            tagged(1, &k[20..]),
        ];
        let (out, _) = run(&policy(Verdict::Redact), &events);
        assert!(!out.contains(&k[..20]) && !out.contains(&k[20..]), "{out}");
    }

    /// AGENT-322: an empty `choices` beside `candidates` (a Gemini client
    /// reads the candidates) does not make the text whole per event.
    #[test]
    fn an_empty_choices_does_not_unwindow_gemini_text() {
        let k = key();
        let with_choices = |t: &str| gemini(t).replacen("{", "{\"choices\":[],", 1);
        let events = vec![
            with_choices(&format!("here: {}", &k[..20])),
            with_choices(&k[20..]),
        ];
        let (out, _) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!out.contains(&k[..20]) && !out.contains(&k[20..]), "{out}");
    }

    /// AGENT-322: clients read a Gemini candidate by position or by
    /// `index`, and a non-boolean `thought` as true (JavaScript) or by
    /// its words (Python), so under `fail_closed` either blocks.
    #[test]
    fn an_ambiguous_gemini_chunk_blocks_under_fail_closed() {
        use serde_json::json;
        let part = |p: serde_json::Value| json!({"content": {"parts": [p]}});
        for (candidates, why) in [
            (
                json!([{"index": 1, "content": {"parts": [{"text": "x"}]}}]),
                "position",
            ),
            (
                json!([part(json!({"text": "x", "thought": "false"}))]),
                "thought",
            ),
            (json!([part(json!({"text": "x", "thought": 1}))]), "thought"),
            (
                json!([part(json!({"text": "x"})), part(json!({"text": "y"}))]),
                "index-less",
            ),
            (
                json!({"0": {"content": {"parts": [{"text": "x"}]}}}),
                "candidates",
            ),
            (
                json!([{"content": {"parts": {"0": {"text": "x"}}}}]),
                "parts",
            ),
        ] {
            let (out, i) = run(
                &closed(1 << 20, Verdict::Redact),
                &[gemini_chunk(candidates)],
            );
            assert!(out.contains("inspection_blocked"), "{why}: {out}");
            assert_eq!(
                i.report().error.as_deref(),
                Some("stream Gemini candidate or part reads two ways"),
                "{why}"
            );
        }
        // `null` candidates (a gateway writing absent fields) name nothing.
        let (_, i) = run(
            &closed(1 << 20, Verdict::Redact),
            &[gemini_chunk(json!(null))],
        );
        assert_eq!(i.report().error, None);
        // Plain ones pass: `index` at its position, a boolean `thought`.
        let plain = json!([
            {"index": 0, "content": {"parts": [{"text": "x", "thought": true}, {"text": "y"}]}},
            {"index": 1, "content": {"parts": [{"text": "z", "thought": false}]}},
        ]);
        let (_, i) = run(&closed(1 << 20, Verdict::Redact), &[gemini_chunk(plain)]);
        assert_eq!(i.report().error, None);
    }

    /// AGENT-322: a protocol `type` beside `candidates` (no real event has
    /// both) does not take the candidates' text out of its window.
    #[test]
    fn a_protocol_type_does_not_unwindow_gemini_text() {
        let k = key();
        let (a, b) = (format!("here: {}", &k[..20]), k[20..].to_string());
        for kind in ["response.output_text.delta", "content_block_delta", "ping"] {
            let typed = |t: &str| gemini(t).replacen("{", &format!("{{\"type\":\"{kind}\","), 1);
            let named = |t: &str| format!("event: {kind}\n{}", gemini(t));
            for events in [vec![typed(&a), typed(&b)], vec![named(&a), named(&b)]] {
                for p in [policy(Verdict::Redact), closed(1 << 20, Verdict::Redact)] {
                    let (out, _) = run(&p, &events);
                    assert!(
                        !out.contains(&k[..20]) && !out.contains(&k[20..]),
                        "{kind}: {out}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_key_split_across_gemini_chunks_is_redacted() {
        let k = key();
        let events = vec![gemini(&format!("here: {}", &k[..20])), gemini(&k[20..])];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!out.contains(&k[..20]), "{out}");
        assert!(!out.contains(&k[20..]), "{out}");
        assert!(i.report().error.is_none());
    }

    #[test]
    fn a_finished_block_is_released_before_the_stream_ends() {
        let mut i = StreamInspector::new(&policy(Verdict::Redact));
        let mut out = i.push(anthropic("short answer").as_bytes()).out;
        let stop =
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n";
        out.extend(i.push(stop.as_bytes()).out);
        let out = String::from_utf8(out.concat()).unwrap();
        assert!(
            out.contains("short answer"),
            "held after its block ended: {out:?}"
        );
    }

    #[test]
    fn a_duplicate_key_cannot_hide_a_value() {
        let event = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{},\"content\":\"safe\"}}}}]}}\n\n",
            q(&key())
        );
        let (out, i) = run(&policy(Verdict::Block), &[event, DONE.to_string()]);
        assert!(!leaked(&out), "{out}");
        assert_eq!(i.report().verdict, Verdict::Block);
    }

    #[test]
    fn a_bom_before_the_first_event_is_ignored() {
        let first = format!("\u{FEFF}{}", chat(&key()));
        let (out, i) = run(&policy(Verdict::Block), &[first, DONE.to_string()]);
        assert!(!leaked(&out), "{out}");
        assert_eq!(i.report().verdict, Verdict::Block);
    }

    #[test]
    fn a_complete_event_past_the_cap_fails_closed() {
        // Little text, so only the event's size can trip the cap.
        let pad = vec!["0"; 2500].join(",");
        let event = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"hi\"}}}}],\"pad\":[{pad}]}}\n\n"
        );
        let mut i = StreamInspector::new(&closed(1024, Verdict::Flag));
        let step = i.push(event.as_bytes());
        assert!(step.ended, "oversized complete event was forwarded");
        let out = String::from_utf8(step.out.concat()).unwrap();
        assert!(out.contains("inspection_blocked") && !out.contains("0,0,0"));
    }

    #[test]
    fn deduplication_state_is_bounded() {
        let mut i = StreamInspector::new(&policy(Verdict::Flag));
        for n in 0..5000 {
            i.push(chat(&format!("AKIA{n:016} ")).as_bytes());
        }
        i.finish();
        assert!(i.seen.len() <= 4 * MAX_AUDITED_HITS, "{}", i.seen.len());
        assert!(i.report().dropped_hits > 0);
    }

    #[test]
    fn text_after_a_finished_output_fails_closed() {
        let stop =
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n";
        let k = key();
        let events = [
            anthropic(&k[..10]),
            stop.to_string(),
            anthropic(&k[10..]),
            PING.to_string(),
        ];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(out.contains("inspection_blocked"), "{out}");
        assert_eq!(i.report().verdict, Verdict::Block);
    }

    #[test]
    fn running_out_of_lanes_fails_closed() {
        let lanes = |n| (0..n).map(|n| chat_n(n, "hi ")).collect::<Vec<String>>();
        let (out, _) = run(&closed(1 << 20, Verdict::Redact), &lanes(MAX_LANES_CLOSED));
        assert!(out.contains("inspection_blocked"), "{out}");
        let (out, _) = run(
            &closed(1 << 20, Verdict::Redact),
            &lanes(MAX_LANES_CLOSED - 1),
        );
        assert!(!out.contains("inspection_blocked"), "{out}");
        let (out, i) = run(&policy(Verdict::Redact), &lanes(MAX_LANES));
        assert!(!out.contains("inspection_blocked") && i.hold_overflowed());
    }

    /// AGENT-273: an output written to after it finished counts against
    /// the lane limit like a new one, so under `fail_open` reopened
    /// outputs past it share a window and memory stays within the limit.
    #[test]
    fn reopened_outputs_past_the_lane_limit_share_a_window() {
        let cap = 1 << 16;
        let p = DirectionPolicy {
            max_scan_bytes: cap,
            ..policy(Verdict::Flag)
        };
        let n = 100;
        let pad = " ".repeat(cap - 1024);
        let mut i = StreamInspector::new(&p);
        for k in 0..n {
            i.push(anthropic_at(k, "a ").as_bytes());
            i.push(anthropic_stop(k).as_bytes());
        }
        for k in 0..n {
            i.push(anthropic_at(k, &pad).as_bytes());
        }
        let held: usize = i.lanes.iter().map(|l| l.window.held()).sum();
        assert!(
            held <= (MAX_LANES + 1) * (cap + cap / 8),
            "{held} bytes held over {} windows",
            i.lanes.iter().filter(|l| l.window.held() > 0).count()
        );
        assert!(i.hold_overflowed());
    }

    #[test]
    fn an_index_written_as_a_float_or_string_is_the_same_output() {
        let k = key();
        let mut events = Vec::new();
        for (n, c) in k.chars().enumerate() {
            let index = ["0", "0.0", "\"0\""][n % 3];
            events.push(format!(
                "data: {{\"choices\":[{{\"index\":{index},\"delta\":{{\"content\":{}}}}}]}}\n\n",
                q(&c.to_string())
            ));
        }
        events.push(DONE.to_string());
        let (_, i) = run(&policy(Verdict::Flag), &events);
        assert_eq!(i.report().hits.len(), 1, "{:?}", i.report().hits);
    }

    fn ev(kind: &str, mut data: serde_json::Value) -> String {
        data["type"] = kind.into();
        format!("event: {kind}\ndata: {data}\n\n")
    }

    fn pieces(text: &str) -> Vec<String> {
        text.split_inclusive(' ').map(str::to_string).collect()
    }

    /// A real provider stream passes untouched under `fail_closed` and
    /// `redact`: nothing blocked, its first (snapshot) event sent at
    /// once, and every byte out before the upstream ends.
    fn passes_whole(events: &[String]) {
        let mut i = StreamInspector::new(&closed(1 << 20, Verdict::Redact));
        let first = i.push(events[0].as_bytes()).out.concat();
        assert_eq!(
            String::from_utf8(first).unwrap(),
            events[0],
            "first event held"
        );
        let mut out = events[0].clone();
        for e in &events[1..] {
            out.push_str(&String::from_utf8(i.push(e.as_bytes()).out.concat()).unwrap());
        }
        assert_eq!(i.report().error, None);
        assert_eq!(out, events.concat());
    }

    fn response(status: &str, output: serde_json::Value) -> serde_json::Value {
        let tools: Vec<_> = (0..10)
            .map(|n| {
                serde_json::json!({"type": "function", "name": format!("tool_{n}"),
                "description": format!("Looks up record number {n}"), "parameters": {}})
            })
            .collect();
        serde_json::json!({"id": "resp_1", "object": "response", "status": status,
            "tool_choice": "auto", "truncation": "disabled", "prompt_cache_key": "pck-1",
            "text": {"format": {"type": "text"}, "verbosity": "medium"},
            "tools": tools, "output": output})
    }

    #[test]
    fn a_responses_message_passes_whole() {
        use serde_json::json;
        let text = "The answer is forty two, as computed.";
        let at = json!({"output_index": 0, "content_index": 0, "item_id": "msg_1"});
        let with = |extra: serde_json::Value| {
            let mut v = at.clone();
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            v
        };
        let item = json!({"id": "msg_1", "type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}]});
        let mut events = vec![
            ev(
                "response.created",
                json!({"response": response("in_progress", json!([]))}),
            ),
            ev(
                "response.in_progress",
                json!({"response": response("in_progress", json!([]))}),
            ),
            ev(
                "response.output_item.added",
                json!({"output_index": 0,
                "item": {"id": "msg_1", "type": "message", "role": "assistant", "content": []}}),
            ),
            ev(
                "response.content_part.added",
                with(json!({"part": {"type": "output_text", "text": "", "annotations": []}})),
            ),
        ];
        for w in pieces(text) {
            events.push(ev(
                "response.output_text.delta",
                with(json!({"delta": w, "obfuscation": "x1"})),
            ));
        }
        events.push(ev("response.output_text.done", with(json!({"text": text}))));
        events.push(ev(
            "response.content_part.done",
            with(json!({"part": {"type": "output_text", "text": text, "annotations": []}})),
        ));
        events.push(ev(
            "response.output_item.done",
            json!({"output_index": 0, "item": item}),
        ));
        events.push(ev(
            "response.completed",
            json!({"response": response("completed", json!([item]))}),
        ));
        passes_whole(&events);
    }

    #[test]
    fn a_responses_function_call_passes_whole() {
        use serde_json::json;
        let args = "{\"city\": \"Paris\", \"unit\": \"c\"}";
        let item = |a: &str| {
            json!({"type": "function_call", "id": "fc_1", "call_id": "call_1",
            "name": "get_weather", "arguments": a})
        };
        let mut events = vec![
            ev(
                "response.created",
                json!({"response": response("in_progress", json!([]))}),
            ),
            ev(
                "response.output_item.added",
                json!({"output_index": 1, "item": item("")}),
            ),
        ];
        for p in pieces(args) {
            events.push(ev(
                "response.function_call_arguments.delta",
                json!({"output_index": 1, "item_id": "fc_1", "delta": p}),
            ));
        }
        events.push(ev(
            "response.function_call_arguments.done",
            json!({"output_index": 1, "item_id": "fc_1", "arguments": args}),
        ));
        events.push(ev(
            "response.output_item.done",
            json!({"output_index": 1, "item": item(args)}),
        ));
        events.push(ev(
            "response.completed",
            json!({"response": response("completed", json!([item(args)]))}),
        ));
        passes_whole(&events);
    }

    #[test]
    fn two_reasoning_summaries_pass_whole() {
        use serde_json::json;
        let mut events = vec![ev(
            "response.output_item.added",
            json!({"output_index": 0, "item": {"type": "reasoning", "id": "rs_1", "summary": []}}),
        )];
        for (n, text) in ["First I read the question.", "Then I checked the sums."]
            .iter()
            .enumerate()
        {
            let at = |extra: serde_json::Value| {
                let mut v = json!({"output_index": 0, "summary_index": n, "item_id": "rs_1"});
                v.as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().unwrap().clone());
                v
            };
            events.push(ev(
                "response.reasoning_summary_part.added",
                at(json!({"part": {"type": "summary_text", "text": ""}})),
            ));
            for p in pieces(text) {
                events.push(ev(
                    "response.reasoning_summary_text.delta",
                    at(json!({"delta": p})),
                ));
            }
            events.push(ev(
                "response.reasoning_summary_text.done",
                at(json!({"text": text})),
            ));
            events.push(ev(
                "response.reasoning_summary_part.done",
                at(json!({"part": {"type": "summary_text", "text": text}})),
            ));
        }
        events.push(ev(
            "response.completed",
            json!({"response": response("completed", json!([]))}),
        ));
        passes_whole(&events);
    }

    #[test]
    fn an_anthropic_stream_with_thinking_and_tools_passes_whole() {
        use serde_json::json;
        let mut events = vec![ev(
            "message_start",
            json!({"message": {"id": "msg_1",
            "type": "message", "role": "assistant", "model": "m", "content": [],
            "stop_reason": null, "usage": {"input_tokens": 10}}}),
        )];
        let block = |events: &mut Vec<String>,
                     n: usize,
                     start: serde_json::Value,
                     deltas: Vec<serde_json::Value>| {
            events.push(ev(
                "content_block_start",
                json!({"index": n, "content_block": start}),
            ));
            for d in deltas {
                events.push(ev("content_block_delta", json!({"index": n, "delta": d})));
            }
            events.push(ev("content_block_stop", json!({"index": n})));
        };
        block(
            &mut events,
            0,
            json!({"type": "thinking", "thinking": "", "signature": ""}),
            vec![
                json!({"type": "thinking_delta", "thinking": "Let me look this up."}),
                json!({"type": "signature_delta", "signature": "c2lnbmVk"}),
            ],
        );
        block(
            &mut events,
            1,
            json!({"type": "text", "text": ""}),
            pieces("I will check two cities.")
                .into_iter()
                .map(|t| json!({"type": "text_delta", "text": t}))
                .collect(),
        );
        for n in 2..4 {
            block(
                &mut events,
                n,
                json!({"type": "tool_use", "id": format!("toolu_{n}"),
                "name": "get_weather", "input": {}}),
                pieces("{\"city\": \"Paris\"}")
                    .into_iter()
                    .map(|p| json!({"type": "input_json_delta", "partial_json": p}))
                    .collect(),
            );
        }
        events.push(ev(
            "message_delta",
            json!({"delta": {"stop_reason": "tool_use",
            "stop_sequence": null}, "usage": {"output_tokens": 50}}),
        ));
        events.push(ev("message_stop", json!({})));
        passes_whole(&events);
    }

    /// A chat stream of `n` parallel tool calls as OpenAI sends them, one
    /// after another: each opened with its name, then given its arguments
    /// in the pieces `args` returns.
    fn parallel_tool_calls(n: usize, args: impl Fn(usize) -> Vec<String>) -> Vec<String> {
        use serde_json::json;
        let chunk = |v: serde_json::Value| format!("data: {v}\n\n");
        let call = |t: usize, f: serde_json::Value| {
            chunk(json!({"id": "c1",
            "choices": [{"index": 0, "delta": {"tool_calls": [{"index": t, "function": f}]}}]}))
        };
        let mut events = vec![chunk(
            json!({"id": "c1", "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]}),
        )];
        for t in 0..n {
            events.push(call(
                t,
                json!({"name": format!("tool_{t}"), "arguments": ""}),
            ));
            for piece in args(t) {
                events.push(call(t, json!({ "arguments": piece })));
            }
        }
        events.push(chunk(
            json!({"id": "c1", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
        ));
        events.push(DONE.to_string());
        events
    }

    /// AGENT-273: each tool call takes two lanes (name and arguments), so
    /// 32 lanes blocked about 15 parallel calls under fail_closed. There the
    /// held text is already bounded across lanes, so more are allowed.
    #[test]
    fn forty_parallel_tool_calls_pass_whole_under_fail_closed() {
        let events = parallel_tool_calls(40, |t| vec!["{\"n\": ".to_string(), format!("{t}}}")]);
        passes_whole(&events);
    }

    /// Token-sized pieces: 40 calls of 300 bytes of arguments each, sent
    /// 6 bytes at a time.
    #[test]
    fn forty_token_streamed_tool_calls_pass_whole_under_fail_closed() {
        let args = format!("{{\"q\": \"{}\"}}", "word ".repeat(58));
        let events = parallel_tool_calls(40, |_| {
            args.as_bytes()
                .chunks(6)
                .map(|c| String::from_utf8(c.to_vec()).unwrap())
                .collect()
        });
        passes_whole(&events);
    }

    /// AGENT-273: a call is finished once the next one starts, so its held
    /// events go then. Before, every call's events queued behind the first
    /// call's held tail until the whole tool-call section, as raw SSE,
    /// passed `max_scan_bytes`: 20 calls of 5 KB sent 6 bytes at a time
    /// (about 2.5 MiB of SSE) blocked at 1 MiB.
    #[test]
    fn a_call_is_released_when_the_next_one_starts() {
        let args = format!("{{\"q\": \"{}\"}}", "word ".repeat(1000));
        let events = parallel_tool_calls(20, |_| {
            args.as_bytes()
                .chunks(6)
                .map(|c| String::from_utf8(c.to_vec()).unwrap())
                .collect()
        });
        passes_whole(&events);
    }

    /// The same, with a key split across the last call's arguments.
    #[test]
    fn a_key_in_the_fortieth_parallel_tool_call_is_redacted() {
        let k = key();
        let events = parallel_tool_calls(40, |t| {
            if t == 39 {
                vec![k[..12].to_string(), k[12..].to_string()]
            } else {
                vec!["{}".to_string()]
            }
        });
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!leaked(&out), "{out}");
        assert!(!out.contains("inspection_blocked"), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    #[test]
    fn chat_with_ten_parallel_tool_calls_passes_whole() {
        use serde_json::json;
        let chunk = |v: serde_json::Value| format!("data: {v}\n\n");
        let safe = json!({"hate": {"filtered": false, "severity": "safe"}});
        let call = |t: usize, f: serde_json::Value| {
            chunk(json!({"id": "c1",
            "choices": [{"index": 0, "delta": {"tool_calls": [{"index": t, "function": f}]}}]}))
        };
        let mut events = vec![
            chunk(json!({"id": "c1", "choices": [],
                "prompt_filter_results": [{"prompt_index": 0, "content_filter_results": safe}]})),
            chunk(
                json!({"id": "c1", "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]}),
            ),
        ];
        for t in 0..10 {
            events.push(call(
                t,
                json!({"name": format!("tool_{t}"), "arguments": ""}),
            ));
            events.push(call(t, json!({"arguments": "{\"n\": "})));
            events.push(call(t, json!({"arguments": format!("{t}}}")})));
        }
        events.push(chunk(
            json!({"id": "c1", "choices": [{"index": 0, "delta": {},
            "finish_reason": "tool_calls", "content_filter_results": safe}]}),
        ));
        events.push(chunk(
            json!({"id": "c1", "choices": [{"index": 0, "delta": {"content": ""}}]}),
        ));
        events.push(chunk(
            json!({"id": "c1", "choices": [], "usage": {"total_tokens": 9}}),
        ));
        events.push(DONE.to_string());
        passes_whole(&events);
    }

    #[test]
    fn a_match_split_between_block_start_and_delta_is_found() {
        use serde_json::json;
        let k = key();
        let events = vec![
            ev(
                "content_block_start",
                json!({"index": 0,
                "content_block": {"type": "text", "text": format!("key: {}", &k[..12])}}),
            ),
            ev(
                "content_block_delta",
                json!({"index": 0,
                "delta": {"type": "text_delta", "text": format!("{} done", &k[12..])}}),
            ),
            ev("content_block_stop", json!({"index": 0})),
            ev("message_stop", json!({})),
        ];
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(!leaked(&out), "{out}");
        assert_eq!(i.report().hits.len(), 1, "{:?}", i.report().hits);
    }

    #[test]
    fn an_escaped_duplicate_value_is_still_inspected() {
        let k = key();
        // `\u0067` is `g`: the hidden value decodes to the key.
        let event = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"\\u0067{}\",\"content\":\"safe\"}}}}]}}\n\n",
            &k[1..]
        );
        for verdict in [Verdict::Redact, Verdict::Block] {
            let (out, i) = run(&policy(verdict), &[event.clone(), DONE.to_string()]);
            assert!(!out.contains(&k[1..9]), "{out}");
            assert_eq!(i.report().verdict, verdict);
        }
    }

    #[test]
    fn a_redacted_root_json_string_stays_json() {
        let k = key();
        let event = format!("data: {}\n\n", q(&format!("key {k} end")));
        let (out, _) = run(&policy(Verdict::Redact), &[event, DONE.to_string()]);
        assert!(!leaked(&out), "{out}");
        for e in sse::SseParser::default().push(out.as_bytes()) {
            let d = e.data.unwrap();
            if d != "[DONE]" {
                let v: serde_json::Value =
                    serde_json::from_str(&d).unwrap_or_else(|_| panic!("{d}"));
                assert!(v.as_str().unwrap().contains("[REDACTED:dlp]"), "{d}");
            }
        }
    }

    /// Every logprob token string in `out`, joined per path with array
    /// positions dropped: what a client reading logprobs rebuilds.
    fn logprob_texts(out: &str) -> Vec<String> {
        fn walk(
            v: &serde_json::Value,
            path: String,
            acc: &mut std::collections::BTreeMap<String, String>,
        ) {
            match v {
                serde_json::Value::Object(m) => {
                    for (k, x) in m {
                        if k == "token" {
                            if let Some(t) = x.as_str() {
                                acc.entry(path.clone()).or_default().push_str(t);
                            }
                        } else if k == "bytes" {
                            let b: Vec<u8> = x
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|n| n.as_u64().map(|n| n as u8))
                                .collect();
                            acc.entry(format!("{path}/bytes"))
                                .or_default()
                                .push_str(&String::from_utf8_lossy(&b));
                        } else {
                            walk(x, format!("{path}/{k}"), acc);
                        }
                    }
                }
                serde_json::Value::Array(a) => {
                    for (i, x) in a.iter().enumerate() {
                        let p = if path.ends_with("top_logprobs") {
                            format!("{path}/{i}")
                        } else {
                            path.clone()
                        };
                        walk(x, p, acc);
                    }
                }
                _ => {}
            }
        }
        let mut acc = std::collections::BTreeMap::new();
        for e in sse::SseParser::default().push(out.as_bytes()) {
            if let Some(v) = e.data.as_deref().and_then(|d| serde_json::from_str(d).ok()) {
                walk(&v, String::new(), &mut acc);
            }
        }
        acc.into_values().collect()
    }

    /// The sampled tokens a client can rebuild from `out`'s logprobs: each
    /// position's `token`, and the `top_logprobs` entry carrying the
    /// sampled logprob (-0.1 here), each joined in order.
    fn sampled_tokens(out: &str) -> [String; 2] {
        fn walk(v: &serde_json::Value, acc: &mut [String; 2]) {
            match v {
                serde_json::Value::Object(m) => {
                    let token = m.get("token").and_then(|t| t.as_str());
                    if let Some(t) = token {
                        if m.contains_key("top_logprobs") {
                            acc[0].push_str(t);
                        } else if m.get("logprob").and_then(|l| l.as_f64()) == Some(-0.1) {
                            acc[1].push_str(t);
                        }
                    }
                    m.values().for_each(|x| walk(x, acc));
                }
                serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, acc)),
                _ => {}
            }
        }
        let mut acc = [String::new(), String::new()];
        for e in sse::SseParser::default().push(out.as_bytes()) {
            if let Some(v) = e.data.as_deref().and_then(|d| serde_json::from_str(d).ok()) {
                walk(&v, &mut acc);
            }
        }
        acc
    }

    #[test]
    fn logprob_tokens_of_a_redacted_match_do_not_leak() {
        use serde_json::json;
        let k = key();
        // The sampled token sits at a different rank at each position.
        let entry = |n: usize, t: &str| {
            let mut top = vec![json!({"token": "x", "logprob": -3.0, "bytes": [120]})];
            top.insert(
                n % 2,
                json!({"token": t, "logprob": -0.1, "bytes": t.as_bytes()}),
            );
            json!({"token": t, "logprob": -0.1, "bytes": t.as_bytes(), "top_logprobs": top})
        };
        let text: Vec<String> = std::iter::once("key: ".to_string())
            .chain(k.chars().map(|c| c.to_string()))
            .chain(std::iter::once(" end".to_string()))
            .collect();
        let all: Vec<_> = text.iter().enumerate().map(|(n, t)| entry(n, t)).collect();
        let chat = |n: usize, t: &str| {
            format!(
                "data: {}\n\n",
                json!({"choices": [{"index": 0,
                "delta": {"content": t}, "logprobs": {"content": [entry(n, t)]}}]})
            )
        };
        let resp = |n: usize, t: &str| {
            ev(
                "response.output_text.delta",
                json!({"output_index": 0, "content_index": 0,
                "delta": t, "logprobs": [entry(n, t)]}),
            )
        };
        type Shape<'a> = &'a dyn Fn(usize, &str) -> String;
        let shapes: [Shape; 2] = [&chat, &resp];
        for (s, event) in shapes.iter().enumerate() {
            let mut events: Vec<String> =
                text.iter().enumerate().map(|(n, t)| event(n, t)).collect();
            if s == 1 {
                // The Responses snapshot repeats the text and every logprob.
                events.push(ev(
                    "response.output_text.done",
                    json!({"output_index": 0,
                    "content_index": 0, "text": text.concat(), "logprobs": all}),
                ));
            }
            events.push(DONE.to_string());
            let (out, _) = run(&policy(Verdict::Redact), &events);
            assert!(!leaked(&out), "{out}");
            let mut rebuilt = logprob_texts(&out).to_vec();
            rebuilt.extend(sampled_tokens(&out));
            for t in rebuilt {
                assert!(
                    (0..=k.len() - 8).all(|i| !t.contains(&k[i..i + 8])),
                    "leaked via logprobs: {t}"
                );
            }
        }
    }

    #[test]
    fn held_events_keep_only_fields_later_text_can_reach() {
        // One byte of text keeps each event held; its other strings are
        // scanned alone and not kept, so they cost nothing while held.
        let key = "k".repeat(200);
        let items = vec!["\"x\""; 100].join(",");
        let event = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"a\"}},\"{key}\":[{items}]}}]}}\n\n"
        );
        let mut i = StreamInspector::new(&closed(1 << 20, Verdict::Redact));
        for _ in 0..10 {
            assert!(!i.push(event.as_bytes()).ended);
        }
        assert_eq!(i.held.len(), 10);
        assert!(
            i.held.iter().all(|h| h.fields.len() == 1),
            "uncut whole fields kept"
        );
        assert!(i.held_bytes <= 10 * (event.len() + 64), "{}", i.held_bytes);
    }

    #[test]
    fn lane_paths_past_the_cap_fail_closed() {
        // Each output finishes at once, so nothing is held: only the
        // remembered lane paths grow.
        let events: Vec<String> = (0..8)
            .map(|n| {
                let key = format!("{n}{}", "p".repeat(4096));
                format!("data: {{\"choices\":[{{\"index\":{n},\"finish_reason\":\"stop\",\"delta\":{{\"{key}\":\"hi\"}}}}]}}\n\n")
            })
            .collect();
        let (out, i) = run(&closed(20_000, Verdict::Redact), &events);
        assert!(out.contains("inspection_blocked"), "{out}");
        assert!(
            i.report()
                .error
                .as_deref()
                .unwrap_or("")
                .contains("outputs")
        );
    }

    #[test]
    fn metadata_names_inside_tool_input_are_scanned() {
        use serde_json::json;
        let k = key();
        let events = vec![
            ev(
                "content_block_start",
                json!({"index": 0, "content_block": {"type": "tool_use",
                "id": "toolu_1", "name": "run", "input": {"instructions": format!("use {k}"),
                    "id": format!("x {k}")}}}),
            ),
            ev("content_block_stop", json!({"index": 0})),
            ev("message_stop", json!({})),
        ];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!out.contains(&k[..12]), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    #[test]
    fn a_snapshot_that_seeds_an_output_fails_closed() {
        use serde_json::json;
        let k = key();
        let responses = vec![
            ev(
                "response.output_item.added",
                json!({"output_index": 0, "item": {"type": "message",
                "id": "m1", "role": "assistant",
                "content": [{"type": "output_text", "text": &k[..12], "annotations": []}]}}),
            ),
            ev(
                "response.output_text.delta",
                json!({"output_index": 0, "content_index": 0, "delta": &k[12..]}),
            ),
            ev("response.completed", json!({"response": {}})),
        ];
        let anthropic = vec![
            ev(
                "message_start",
                json!({"message": {"id": "m1", "role": "assistant",
                "content": [{"type": "text", "text": &k[..12]}]}}),
            ),
            ev(
                "content_block_delta",
                json!({"index": 0,
                "delta": {"type": "text_delta", "text": &k[12..]}}),
            ),
            ev("message_stop", json!({})),
        ];
        for events in [responses, anthropic] {
            let (out, i) = run(&closed(1 << 20, Verdict::Block), &events);
            assert!(out.contains("inspection_blocked") && !leaked(&out), "{out}");
            assert!(i.report().error.is_some(), "{:?}", i.report());
            let (out, i) = run(&policy(Verdict::Flag), &events);
            assert!(!out.contains("inspection_blocked"));
            assert!(i.hold_overflowed(), "fail_open notes the seed");
        }
    }

    #[test]
    fn a_match_split_between_an_added_refusal_and_a_delta_is_found() {
        use serde_json::json;
        let k = key();
        let at = |extra: serde_json::Value| {
            let mut v = json!({"output_index": 0, "content_index": 0});
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            v
        };
        let events = vec![
            ev(
                "response.content_part.added",
                at(json!({"part": {"type": "refusal", "refusal": format!("no {}", &k[..12])}})),
            ),
            ev(
                "response.refusal.delta",
                at(json!({"delta": format!("{} end", &k[12..])})),
            ),
            ev("response.completed", json!({"response": {}})),
        ];
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(
            !out.contains(&k[..12]) && !out.contains(&k[12..24]),
            "{out}"
        );
        assert_eq!(i.report().hits.len(), 1, "{:?}", i.report().hits);
    }

    #[test]
    fn a_match_split_between_added_text_and_a_delta_is_found() {
        use serde_json::json;
        let k = key();
        let at = |extra: serde_json::Value| {
            let mut v = json!({"output_index": 0, "content_index": 0});
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            v
        };
        let events = vec![
            ev(
                "response.content_part.added",
                at(json!({"part": {"type": "output_text", "text": format!("key {}", &k[..12])}})),
            ),
            ev(
                "response.output_text.delta",
                at(json!({"delta": format!("{} end", &k[12..])})),
            ),
            ev("response.output_text.done", at(json!({"text": "[elided]"}))),
            ev("response.completed", json!({"response": {}})),
        ];
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(
            !out.contains(&k[..12]) && !out.contains(&k[12..24]),
            "{out}"
        );
        assert_eq!(i.report().hits.len(), 1, "{:?}", i.report().hits);
    }

    #[test]
    fn finished_outputs_do_not_count_toward_the_lane_limit() {
        use serde_json::json;
        let mut events = Vec::new();
        for n in 0..(2 * MAX_LANES) {
            events.push(ev(
                "content_block_start",
                json!({"index": n, "content_block": {"type": "text", "text": ""}}),
            ));
            events.push(ev(
                "content_block_delta",
                json!({"index": n, "delta": {"type": "text_delta", "text": "hi"}}),
            ));
            events.push(ev("content_block_stop", json!({"index": n})));
        }
        events.push(ev("message_stop", json!({})));
        passes_whole(&events);
    }

    #[test]
    fn an_event_whose_paths_outweigh_the_cap_is_oversize() {
        // Few bytes of text, but each string's path repeats a long key.
        let long = "k".repeat(4096);
        let items = vec!["\"a\""; 2000].join(",");
        let event = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"{long}\":[{items}]}}}}]}}\n\n"
        );
        assert!(event.len() < 1 << 20);
        let mut i = StreamInspector::new(&closed(1 << 20, Verdict::Redact));
        let step = i.push(event.as_bytes());
        assert!(step.ended, "paths past the cap were accepted");
        assert_eq!(i.report().skipped, Some(super::super::SkipReason::Oversize));
    }

    #[test]
    fn past_an_oversize_event_fail_open_forwards_the_rest_in_order() {
        let long = "k".repeat(4096);
        let items = vec!["\"a\""; 2000].join(",");
        let big = format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"{long}\":[{items}]}}}}]}}\n\n"
        );
        // A held delta before, one after, and a partial event at the end:
        // all of it goes out with this push, unheld.
        let batch = [chat("one "), big, chat("two "), "data: {\"par".to_string()].concat();
        let mut i = StreamInspector::new(&policy(Verdict::Redact));
        let first = String::from_utf8(i.push(batch.as_bytes()).out.concat()).unwrap();
        assert_eq!(first, batch);
        let rest = String::from_utf8(i.push(b"tial\"}\n\n").out.concat()).unwrap();
        assert_eq!(rest, "tial\"}\n\n");
        assert!(i.finish().out.is_empty());
        assert_eq!(i.report().skipped, Some(super::super::SkipReason::Oversize));
    }

    #[test]
    fn an_oversize_last_event_under_fail_open_ends_without_a_block() {
        let long = "k".repeat(4096);
        let items = vec!["\"a\""; 2000].join(",");
        let big =
            format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"{long}\":[{items}]}}}}]}}");
        let mut i = StreamInspector::new(&DirectionPolicy {
            on_error: OnError::FailOpen,
            ..policy(Verdict::Block)
        });
        // Clean text is still held when the oversize last event ends the
        // stream: once the stream has passed through, finish() judges
        // nothing more, so no block follows what was already sent. (A key
        // held then is judged before anything is released; see
        // an_oversized_event_does_not_release_held_text_unscanned.)
        let mut out = i.push(chat(&"x ".repeat(500)).as_bytes()).out;
        out.extend(i.push(big.as_bytes()).out);
        out.extend(i.finish().out);
        let out = String::from_utf8(out.concat()).unwrap();
        assert!(
            !out.contains("inspection_blocked"),
            "{}",
            &out[out.len().saturating_sub(300)..]
        );
        assert!(out.ends_with(&big));
    }

    #[test]
    fn object_keys_are_scanned() {
        use serde_json::json;
        let k = key();
        let events = vec![
            ev(
                "content_block_start",
                json!({"index": 0, "content_block": {"type": "tool_use",
                "id": "toolu_1", "name": "run", "input": {k.clone(): "safe"}}}),
            ),
            ev("content_block_stop", json!({"index": 0})),
            ev("message_stop", json!({})),
        ];
        let (out, i) = run(&closed(1 << 20, Verdict::Block), &events);
        assert!(
            out.contains("inspection_blocked") && !out.contains(&k[..12]),
            "{out}"
        );
        assert_eq!(i.report().verdict, Verdict::Block);
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!out.contains(&k[..12]), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
        for e in sse::SseParser::default().push(out.as_bytes()) {
            serde_json::from_str::<serde_json::Value>(&e.data.unwrap()).unwrap();
        }
    }

    /// AGENT-323: an MCP task list and the server's own MCP requests are
    /// complete in their events too, so they pass whole, while a key inside
    /// one is still caught. A method MCP does not name keeps its windows
    /// and still blocks past the limit.
    #[test]
    fn large_mcp_tasks_and_server_requests_pass_whole() {
        let k = key();
        let many = |f: &dyn Fn(usize) -> serde_json::Value| -> Vec<serde_json::Value> {
            (0..300).map(f).collect()
        };
        let text = |n: usize| {
            if n == 150 {
                format!("item {n} with {k}")
            } else {
                format!("item {n}")
            }
        };
        let tasks = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {
            "tasks": many(&|n| serde_json::json!({"taskId": format!("t{n}"), "statusMessage": text(n)}))}});
        let sampling = serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "sampling/createMessage",
            "params": {"maxTokens": 10, "messages": many(&|n| serde_json::json!({
                "role": "user", "content": {"type": "text", "text": text(n)}}))}});
        let elicit = serde_json::json!({"jsonrpc": "2.0", "id": 8, "method": "elicitation/create",
            "params": {"message": "fill in", "requestedSchema": {"type": "object",
                "properties": many(&|n| serde_json::json!({"type": "string", "description": text(n)}))}}});
        for (name, message) in [("tasks", tasks), ("sampling", sampling), ("elicit", elicit)] {
            let event = format!("event: message\ndata: {message}\n\n");
            let (out, i) = run(&closed(1 << 20, Verdict::Redact), &[event]);
            assert_eq!(i.report().error, None, "{name}");
            assert!(out.contains("item 299"), "{name}");
            assert!(!out.contains(&k[..12]), "{name}");
            assert_eq!(i.report().verdict, Verdict::Redact, "{name}");
        }
        let other = serde_json::json!({"jsonrpc": "2.0", "method": "session/update",
            "params": {"data": many(&|n| serde_json::json!(format!("item {n}")))}});
        let event = format!("data: {other}\n\n");
        let (_, i) = run(&closed(1 << 20, Verdict::Redact), &[event]);
        assert_eq!(
            i.report().error.as_deref(),
            Some("more stream outputs than can be inspected")
        );
    }

    /// AGENT-323: MCP notifications (progress, log messages) arrive over
    /// time and keep their windows, so a key split across two of them is
    /// still caught; and a
    /// message that is not a plain MCP result or request (it carries both
    /// `result` and `method`, or an `error`) is not scanned whole.
    #[test]
    fn other_mcp_shapes_keep_their_windows() {
        let k = key();
        let progress = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/progress",
                    "params": {"progressToken": 1, "progress": 1, "message": t}})
            )
        };
        let log = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/message",
                    "params": {"level": "info", "logger": "tool", "data": t}})
            )
        };
        for events in [
            vec![progress(&format!("token {}", &k[..20])), progress(&k[20..])],
            vec![log(&format!("token {}", &k[..20])), log(&k[20..])],
        ] {
            let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert!(!out.contains(&k[..20]) && !out.contains(&k[20..]), "{out}");
            assert_eq!(i.report().verdict, Verdict::Redact);
        }
        let many: Vec<_> = (0..300)
            .map(|n| serde_json::json!(format!("item {n}")))
            .collect();
        let shapes = [
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "x",
                "result": {"tools": many}}),
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 1, "message": "e"},
                "result": {"tools": many}}),
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage",
                "error": {"code": 1, "message": "e"}, "params": {"messages": many}}),
        ];
        for shape in shapes {
            let (_, i) = run(
                &closed(1 << 20, Verdict::Redact),
                &[format!("data: {shape}\n\n")],
            );
            assert_eq!(
                i.report().error.as_deref(),
                Some("more stream outputs than can be inspected")
            );
        }
    }

    /// AGENT-273: an MCP result is complete in its event, so the strings
    /// of a large `tools/list` result are scanned whole instead of taking
    /// a window each and blocking past the lane limit.
    #[test]
    fn a_large_mcp_result_passes_under_fail_closed() {
        let k = key();
        let tools: Vec<_> = (0..300)
            .map(|n| {
                let description = if n == 150 {
                    format!("does thing {n} with {k}")
                } else {
                    format!("does thing {n}")
                };
                serde_json::json!({"name": format!("tool{n}"), "description": description})
            })
            .collect();
        let event = format!(
            "event: message\ndata: {}\n\n",
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}})
        );
        let (out, i) = run(
            &closed(1 << 20, Verdict::Redact),
            std::slice::from_ref(&event),
        );
        assert_eq!(i.report().error, None);
        assert!(out.contains("does thing 299"), "{out}");
        // Scanned whole, a key inside one string is still caught.
        assert!(!out.contains(&k[..12]), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    /// AGENT-273: the stream's first JSON event decides whether it is
    /// JSON-RPC, so a `jsonrpc` field added mid-stream to another
    /// protocol's events does not take their text out of its windows.
    #[test]
    fn a_jsonrpc_field_mid_stream_keeps_its_windows() {
        let k = key();
        let generic = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"result": {"content": [{"type": "text", "text": t}]}})
            )
        };
        let rpc = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"jsonrpc": "2.0", "id": 1,
                    "result": {"content": [{"type": "text", "text": t}]}})
            )
        };
        let events = vec![generic(&format!("here: {}", &k[..20])), rpc(&k[20..])];
        let (out, _) = run(&policy(Verdict::Redact), &events);
        assert!(!out.contains(&k[..20]) && !out.contains(&k[20..]), "{out}");
        // Under `fail_closed`, a JSON-RPC stream turning into something
        // else blocks, as a change of protocol does.
        let events = vec![rpc("hello"), generic("world")];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(out.contains("inspection_blocked"), "{out}");
        assert_eq!(
            i.report().error.as_deref(),
            Some("stream event names another protocol")
        );
        // Under `fail_open` it goes on, audited as a hold overflow.
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(out.contains("world"), "{out}");
        assert_eq!(i.report().error, None);
        assert!(i.hold_overflowed());
    }

    /// AGENT-273: A2A streams artifact chunks as JSON-RPC results that
    /// clients append to one another, so they keep their windows.
    #[test]
    fn a2a_artifact_chunks_keep_their_windows() {
        let k = key();
        let chunk = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {
                    "kind": "artifact-update", "append": true, "artifact": {
                        "artifactId": "a1", "parts": [{"kind": "text", "text": t}]},
                    // An MCP result's member beside them scans only itself whole.
                    "content": []}})
            )
        };
        let status = format!(
            "data: {}\n\n",
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {
                "kind": "status-update", "status": {"state": "working"}}})
        );
        // Chunks after a status update are still the same JSON-RPC stream.
        let events = vec![
            status,
            chunk(&format!("here: {}", &k[..18])),
            chunk(&k[18..]),
        ];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!out.contains(&k[..18]) && !out.contains(&k[18..]), "{out}");
        assert_eq!(i.report().error, None);
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    /// AGENT-273: a `jsonrpc` field beside another protocol's fields does
    /// not make its events JSON-RPC messages, so their text keeps its
    /// windows.
    #[test]
    fn a_jsonrpc_field_on_another_protocol_keeps_its_windows() {
        let k = key();
        let delta = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"jsonrpc": "2.0", "type": "content-delta", "index": 0,
                    "delta": {"message": {"content": {"text": t}}}})
            )
        };
        let events = vec![delta(&format!("here: {}", &k[..18])), delta(&k[18..])];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!out.contains(&k[..18]) && !out.contains(&k[18..]), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    /// AGENT-273: only MCP results are scanned whole. Other JSON-RPC
    /// streams whose clients join text across messages (A2A 1.0 artifact
    /// updates, ACP session updates) keep their windows.
    #[test]
    fn other_jsonrpc_chunks_keep_their_windows() {
        let k = key();
        let task = format!(
            "data: {}\n\n",
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"task": {
                "id": "t1", "status": {"state": "TASK_STATE_SUBMITTED"}}}})
        );
        let a2a = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"artifactUpdate": {
                    "append": true, "artifact": {"artifactId": "a1", "parts": [{"text": t}]}}}})
            )
        };
        let acp = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"jsonrpc": "2.0", "method": "session/update", "params": {
                    "sessionId": "s1", "update": {"sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": t}}}})
            )
        };
        let streams = [
            vec![task, a2a(&format!("here: {}", &k[..18])), a2a(&k[18..])],
            vec![acp(&format!("here: {}", &k[..18])), acp(&k[18..])],
        ];
        for events in streams {
            let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
            assert!(!out.contains(&k[..18]) && !out.contains(&k[18..]), "{out}");
            assert_eq!(i.report().error, None);
            assert_eq!(i.report().verdict, Verdict::Redact);
        }
    }

    /// AGENT-273: a message with a member JSON-RPC does not define is not
    /// an MCP result, so its text keeps its windows.
    #[test]
    fn an_mcp_shape_with_a_foreign_member_keeps_its_windows() {
        let k = key();
        let message = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "_x": 1,
                    "result": {"content": [{"type": "text", "text": t}]}})
            )
        };
        let events = vec![message(&format!("here: {}", &k[..18])), message(&k[18..])];
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(!out.contains(&k[..18]) && !out.contains(&k[18..]), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    /// AGENT-273: a JSON-RPC message with a member the spec does not name,
    /// or a batch, is still JSON-RPC, so it does not end the stream.
    #[test]
    fn jsonrpc_extras_and_batches_stay_jsonrpc() {
        let first = format!(
            "data: {}\n\n",
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
        );
        let extra = format!(
            "data: {}\n\n",
            serde_json::json!({"jsonrpc": "2.0", "method": "log", "params": {}, "_meta": {}})
        );
        let batch = format!(
            "data: {}\n\n",
            serde_json::json!([{"jsonrpc": "2.0", "id": 2, "result": {}}])
        );
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &[first, extra, batch]);
        assert_eq!(i.report().error, None, "{out}");
        assert!(!out.contains("inspection_blocked"), "{out}");
    }

    #[test]
    fn metadata_names_in_application_data_are_scanned() {
        let k = key();
        let event = format!(
            "data: {}\n\n",
            serde_json::json!({"jsonrpc": "2.0",
            "result": {"instructions": format!("use {k}"), "status": format!("{k}")}})
        );
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &[event]);
        assert!(!out.contains(&k[..12]), "{out}");
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    #[test]
    fn undecodable_json_follows_on_error() {
        let k = key();
        // `1e400` is out of range, so the data does not parse, and the key
        // is only visible once `\u0067` is decoded.
        let event = format!("data: {{\"x\":1e400,\"t\":\"\\u0067{}\"}}\n\n", &k[1..]);
        let (out, i) = run(
            &closed(1 << 20, Verdict::Flag),
            std::slice::from_ref(&event),
        );
        assert!(out.contains("inspection_blocked"), "fail_closed: {out}");
        assert!(i.report().error.is_some());
        for verdict in [Verdict::Redact, Verdict::Block] {
            let (out, i) = run(&policy(verdict), std::slice::from_ref(&event));
            assert!(!out.contains(&k[1..9]), "{verdict:?}: {out}");
            assert_eq!(i.report().verdict, Verdict::Block);
        }
    }

    #[test]
    fn escapes_in_any_unparsed_data_are_resolved() {
        let k = key();
        // A JSON string left open, and plain text, each hiding the key
        // behind `\u0067`.
        let open = format!("data: \"\\u0067{}\n\n", &k[1..]);
        let plain = format!("data: key \\u0067{} end\n\n", &k[1..]);
        let (out, i) = run(&closed(1 << 20, Verdict::Flag), std::slice::from_ref(&open));
        assert!(out.contains("inspection_blocked"), "fail_closed: {out}");
        assert!(i.report().error.is_some());
        for event in [open, plain] {
            let (out, i) = run(&policy(Verdict::Block), std::slice::from_ref(&event));
            assert!(!out.contains(&k[1..9]), "{out}");
            assert_eq!(i.report().verdict, Verdict::Block);
        }
    }

    #[test]
    fn a_redaction_no_rewrite_can_reach_is_marked_incomplete() {
        // AGENT-270: as for a buffered body, a redact that has to block
        // says why in the audit row.
        let k = key();
        let plain = format!("data: key \\u0067{} end\n\n", &k[1..]);
        let (out, i) = run(&policy(Verdict::Redact), std::slice::from_ref(&plain));
        assert!(out.contains("inspection_blocked"), "{out}");
        assert_eq!(i.report().verdict, Verdict::Block);
        assert!(i.report().redaction_incomplete);
        let (_, i) = run(&policy(Verdict::Block), std::slice::from_ref(&plain));
        assert!(!i.report().redaction_incomplete, "a block policy");
    }

    #[test]
    fn a_metadata_name_in_another_protocol_keeps_its_lane() {
        let k = key();
        let mut events: Vec<String> = k
            .chars()
            .map(|c| format!("data: {}\n\n", serde_json::json!({"status": c.to_string()})))
            .collect();
        events.push(DONE.to_string());
        let (_, i) = run(&policy(Verdict::Flag), &events);
        assert_eq!(i.report().hits.len(), 1, "{:?}", i.report().hits);
    }

    #[test]
    fn a_key_inside_a_hidden_value_is_scanned() {
        let k = key();
        let event = format!("data: {{\"x\":{{\"{k}\":1}},\"x\":null}}\n\n");
        for verdict in [Verdict::Redact, Verdict::Block] {
            let (out, i) = run(&policy(verdict), std::slice::from_ref(&event));
            assert!(!out.contains(&k[..12]), "{verdict:?}: {out}");
            assert_eq!(i.report().verdict, verdict);
        }
    }

    #[test]
    fn a_long_realistic_chat_stream_passes_under_fail_closed() {
        use serde_json::json;
        let chunk = |c: serde_json::Value, finish: serde_json::Value| {
            format!(
                "data: {}\n\n",
                json!({"id": "chatcmpl-AbCdEf0123456789", "object":
                "chat.completion.chunk", "created": 1_700_000_000, "model": "gpt-x-2026-01-01",
                "system_fingerprint": "fp_0123456789", "choices": [{"index": 0, "delta": c,
                "logprobs": null, "finish_reason": finish}]})
            )
        };
        let mut events = vec![chunk(
            json!({"role": "assistant", "content": ""}),
            json!(null),
        )];
        for n in 0..3000 {
            events.push(chunk(
                json!({"content": format!("w{} ", n % 10)}),
                json!(null),
            ));
        }
        events.push(chunk(json!({}), json!("stop")));
        events.push(DONE.to_string());
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert_eq!(i.report().error, None);
        assert!(!i.hold_overflowed());
        assert_eq!(out, events.concat());
    }

    #[test]
    fn a_long_line_in_small_chunks_parses_in_linear_time() {
        let mut p = sse::SseParser::default();
        let line = format!("data: {}", "x".repeat(1 << 20));
        let started = std::time::Instant::now();
        for chunk in line.as_bytes().chunks(64) {
            assert!(p.push(chunk).is_empty());
        }
        assert_eq!(p.push(b"\n\n").len(), 1);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_changing_top_level_index_does_not_split_a_chat_choice() {
        let k = key();
        let events: Vec<String> = k
            .chars()
            .enumerate()
            .map(|(n, c)| {
                format!(
                    "data: {}\n\n",
                    serde_json::json!({"index": n % 2,
                    "choices": [{"index": 0, "delta": {"content": c.to_string()}}]})
                )
            })
            .chain(std::iter::once(DONE.to_string()))
            .collect();
        let (out, i) = run(&closed(1 << 20, Verdict::Block), &events);
        assert!(out.contains("inspection_blocked") && !leaked(&out), "{out}");
        assert_eq!(i.report().hits.len(), 1, "{:?}", i.report());
        // Anthropic blocks are keyed by `index` only: an `output_index`
        // does not split one.
        let anthropic: Vec<String> = k
            .chars()
            .enumerate()
            .map(|(n, c)| {
                ev(
                    "content_block_delta",
                    serde_json::json!({"index": 0,
                "output_index": n % 2, "delta": {"type": "text_delta", "text": c.to_string()}}),
                )
            })
            .chain(std::iter::once(ev("message_stop", serde_json::json!({}))))
            .collect();
        let (out, i) = run(&closed(1 << 20, Verdict::Block), &anthropic);
        assert!(out.contains("inspection_blocked") && !leaked(&out), "{out}");
        assert_eq!(i.report().hits.len(), 1, "{:?}", i.report());
    }

    #[test]
    fn an_event_whose_name_and_type_disagree_fails_closed() {
        let k = key();
        // A client dispatching on the event name joins the second piece
        // to block 0; one reading `type` would not.
        let first = ev(
            "content_block_delta",
            serde_json::json!({"index": 0,
            "delta": {"type": "text_delta", "text": &k[..20]}}),
        );
        let odd = format!(
            "event: content_block_delta\ndata: {}\n\n",
            serde_json::json!({
            "type": "message_delta", "index": 0, "delta": {"type": "text_delta", "text": &k[20..]}})
        );
        let events = [first, odd, ev("message_stop", serde_json::json!({}))];
        let (out, i) = run(&closed(1 << 20, Verdict::Block), &events);
        assert!(out.contains("inspection_blocked") && !leaked(&out), "{out}");
        assert!(i.report().error.is_some() || !i.report().hits.is_empty());
    }

    #[test]
    fn an_event_named_for_a_protocol_with_another_type_fails_closed() {
        let named = |t: &str| {
            format!(
                "event: content_block_delta\ndata: {}\n\n",
                serde_json::json!({
            "type": "x_delta", "index": 0, "delta": {"type": "text_delta", "text": t}})
            )
        };
        let (out, i) = run(&closed(1 << 20, Verdict::Block), &[named("hi")]);
        assert!(out.contains("inspection_blocked"), "{out}");
        assert!(i.report().error.is_some());
        let error = format!(
            "event: content_block_delta\ndata: {}\n\n",
            serde_json::json!({
            "type": "error", "index": 0, "delta": {"type": "text_delta", "text": "hi"}})
        );
        let (out, _) = run(&closed(1 << 20, Verdict::Block), &[error]);
        assert!(out.contains("inspection_blocked"), "{out}");
        // The SSE default name `message` names no event type.
        let plain = format!(
            "event: message\ndata: {}\n\n",
            serde_json::json!({
            "type": "response.output_text.delta", "output_index": 0, "content_index": 0,
            "delta": "hi"})
        );
        let (out, i) = run(&closed(1 << 20, Verdict::Block), &[plain]);
        assert!(!out.contains("inspection_blocked"), "{out}");
        assert_eq!(i.report().error, None);
    }

    #[test]
    fn a_stream_that_changes_protocol_fails_closed() {
        let k = key();
        let events = [
            ev(
                "content_block_delta",
                serde_json::json!({"index": 0,
                "delta": {"type": "text_delta", "text": &k[..20]}}),
            ),
            ev(
                "response.output_text.delta",
                serde_json::json!({"output_index": 0,
                "content_index": 0, "delta": &k[20..]}),
            ),
            ev("message_stop", serde_json::json!({})),
        ];
        let (out, i) = run(&closed(1 << 20, Verdict::Block), &events);
        assert!(out.contains("inspection_blocked") && !leaked(&out), "{out}");
        assert!(
            i.report()
                .error
                .as_deref()
                .unwrap_or("")
                .contains("protocol"),
            "{:?}",
            i.report()
        );
    }

    #[test]
    fn an_index_a_responses_event_does_not_use_does_not_split_it() {
        let k = key();
        let text: Vec<String> = k
            .chars()
            .enumerate()
            .map(|(n, c)| {
                ev(
                    "response.output_text.delta",
                    serde_json::json!({"output_index": 0,
                "content_index": 0, "summary_index": n % 2, "delta": c.to_string()}),
                )
            })
            .chain(std::iter::once(ev(
                "response.completed",
                serde_json::json!({"response": {}}),
            )))
            .collect();
        let args: Vec<String> = k
            .chars()
            .enumerate()
            .map(|(n, c)| {
                ev(
                    "response.function_call_arguments.delta",
                    serde_json::json!({
                "output_index": 1, "content_index": n % 2, "delta": c.to_string()}),
                )
            })
            .chain(std::iter::once(ev(
                "response.completed",
                serde_json::json!({"response": {}}),
            )))
            .collect();
        for events in [text, args] {
            let (out, i) = run(&closed(1 << 20, Verdict::Block), &events);
            assert!(out.contains("inspection_blocked") && !leaked(&out), "{out}");
            assert_eq!(i.report().hits.len(), 1, "{:?}", i.report());
        }
    }

    #[test]
    fn an_empty_choices_array_does_not_turn_off_windows() {
        let k = key();
        let anthropic: Vec<String> = k
            .chars()
            .map(|c| {
                ev(
                    "content_block_delta",
                    serde_json::json!({"index": 0, "choices": [],
                "delta": {"type": "text_delta", "text": c.to_string()}}),
                )
            })
            .chain(std::iter::once(ev("message_stop", serde_json::json!({}))))
            .collect();
        let responses: Vec<String> = k
            .chars()
            .map(|c| {
                ev(
                    "response.output_text.delta",
                    serde_json::json!({"output_index": 0,
                "content_index": 0, "choices": [], "delta": c.to_string()}),
                )
            })
            .chain(std::iter::once(ev(
                "response.completed",
                serde_json::json!({"response": {}}),
            )))
            .collect();
        for events in [anthropic, responses] {
            let (out, i) = run(&closed(1 << 20, Verdict::Block), &events);
            assert!(out.contains("inspection_blocked") && !leaked(&out), "{out}");
            assert_eq!(i.report().hits.len(), 1, "{:?}", i.report());
        }
    }

    #[test]
    fn unparseable_json_without_escapes_fails_closed() {
        let k = key();
        let events: Vec<String> = k
            .chars()
            .map(|c| format!("data: {{\"x\":1e400,\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{c}\"}}}}]}}\n\n"))
            .collect();
        let (out, i) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(out.contains("inspection_blocked"), "{out}");
        assert!(i.report().error.is_some());
    }

    #[test]
    fn dense_hits_in_one_event_scan_in_linear_time() {
        let canary = "CANARY42";
        let scanner: Arc<dyn Scanner> =
            Arc::new(super::super::literal::Literal::new(canary).unwrap());
        let p = DirectionPolicy {
            scanners: vec![scanner],
            ..policy(Verdict::Flag)
        };
        let text = format!("{canary} ").repeat(60_000);
        let event = format!("data: {}\n\n", serde_json::json!({"x": text}));
        let started = std::time::Instant::now();
        let (_, i) = run(&p, &[event]);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(!i.report().hits.is_empty());
    }

    /// AGENT-315: a stream that redacts keeps scanning every push past a
    /// full window, so under `fail_open` a key is still found while its
    /// events are held, even when the held events pass the limit. If its
    /// start went early regardless, the stream blocks (AGENT-330).
    #[test]
    fn a_key_streamed_past_a_full_window_is_never_sent_in_part() {
        let mut outcomes = Vec::new();
        for cap in [4096, 1 << 14] {
            for per in [1, 3] {
                let mut events: Vec<String> = (0..2 * cap / 2048 + 1)
                    .map(|_| chat(&" ".repeat(2048)))
                    .collect();
                let secret: Vec<char> = format!(" {} ", key()).chars().collect();
                events.extend(
                    secret
                        .chunks(per)
                        .map(|c| chat(&c.iter().collect::<String>())),
                );
                events.extend((0..cap / 32).map(|_| chat("  ")));
                events.push(chat(" done."));
                events.push(DONE.to_string());
                let p = DirectionPolicy {
                    max_scan_bytes: cap,
                    ..policy(Verdict::Redact)
                };
                let (out, i) = run(&p, &events);
                assert!(!leaked(&out), "cap {cap}, {per} a time: the key went out");
                assert!(i.hold_overflowed());
                // A redaction removes the key whole, its start included;
                // one that can't, its start already sent, blocks (AGENT-330).
                let text = client_texts(&out).concat();
                match i.report().verdict {
                    Verdict::Redact => {
                        assert!(text.contains("[REDACTED:dlp]") && text.contains("done."));
                        assert!(!i.report().redaction_incomplete);
                    }
                    v => {
                        assert_eq!(v, Verdict::Block);
                        assert!(i.report().redaction_incomplete);
                    }
                }
                outcomes.push(i.report().verdict);
            }
        }
        assert!(outcomes.contains(&Verdict::Redact) && outcomes.contains(&Verdict::Block));
    }

    /// A chat delta whose event also carries a long `id`, so few events fit
    /// in `max_scan_bytes` and the oldest go early.
    fn chat_with_id(d: &str) -> String {
        chat_with_id_of(191, d)
    }

    fn chat_with_id_of(digits: usize, d: &str) -> String {
        format!(
            "data: {{\"id\":\"chatcmpl-{}\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{}}}}}]}}\n\n",
            "0".repeat(digits),
            q(d)
        )
    }

    /// AGENT-330: under `fail_open`, events can go early before the key in
    /// them is complete. A key whose start already went out can't be
    /// removed whole: the stream is blocked, not reported as redacted.
    #[test]
    fn a_key_begun_in_text_sent_early_blocks_the_stream() {
        let mut events = vec![PING.to_string()];
        events.extend((0..9).map(|_| chat(&" ".repeat(1000))));
        events.extend((0..50).map(|_| chat_with_id("z")));
        let secret: Vec<char> = format!(" {} ", key()).chars().collect();
        events.extend(secret.iter().map(|c| chat_with_id(&c.to_string())));
        events.extend((0..256).map(|_| chat_with_id(" y")));
        events.push(DONE.to_string());
        let p = DirectionPolicy {
            max_scan_bytes: 4096,
            ..policy(Verdict::Redact)
        };
        let (out, i) = run(&p, &events);
        assert!(i.hold_overflowed());
        assert!(out.contains("inspection_blocked"), "{out}");
        assert!(i.report().redaction_incomplete);
        assert_eq!(i.report().verdict, Verdict::Block);
    }

    /// AGENT-330: a PEM key grows past what was scanned; its newest lines
    /// can go early before the scan that grows the match over them. They
    /// can't be cut once sent, so the stream is blocked.
    #[test]
    fn a_key_grown_into_text_sent_early_blocks_the_stream() {
        let line = "QUJD".repeat(16);
        let mut events = vec![chat_with_id_of(1500, "Here: -----BEGIN PRIVATE KEY-----\n")];
        events.extend((0..60).map(|_| chat_with_id_of(1500, &format!("{line}\n"))));
        events.push(chat_with_id_of(
            1500,
            "-----END PRIVATE KEY----- that is all.",
        ));
        events.push(DONE.to_string());
        let p = DirectionPolicy {
            max_scan_bytes: 4096,
            ..policy(Verdict::Redact)
        };
        let (out, i) = run(&p, &events);
        assert!(i.hold_overflowed());
        let sent = client_texts(&out).concat().contains("QUJD");
        assert!(sent, "the test sends a line before it is scanned");
        assert!(out.contains("inspection_blocked"), "{out}");
        assert!(i.report().redaction_incomplete);
    }

    /// AGENT-330: a key's lines that went early after they were scanned and
    /// cut gave nothing away; only their trailing newlines, which the match
    /// grows over later, went with them. The key is still redacted.
    #[test]
    fn a_key_grown_over_sent_whitespace_is_still_redacted() {
        let line = "QUJD".repeat(16);
        let mut events = vec![chat_with_id_of(300, "Here: -----BEGIN PRIVATE KEY-----\n")];
        events.extend((0..60).map(|_| chat_with_id_of(300, &format!("{line}\n"))));
        events.push(chat_with_id_of(
            300,
            "-----END PRIVATE KEY----- that is all.",
        ));
        events.push(DONE.to_string());
        let p = DirectionPolicy {
            max_scan_bytes: 4096,
            ..policy(Verdict::Redact)
        };
        let (out, i) = run(&p, &events);
        assert!(i.hold_overflowed());
        let text = client_texts(&out).concat();
        assert!(!text.contains("QUJD"), "{text}");
        assert!(text.contains("that is all."), "{text}");
        assert_eq!(i.report().verdict, Verdict::Redact);
        assert!(!i.report().redaction_incomplete);
    }

    /// The same with the whitespace after each line in events of its own,
    /// and with the key in tool-call arguments, where its newlines are
    /// escaped: whitespace sent early gives nothing away either.
    #[test]
    fn a_key_grown_over_whitespace_sent_on_its_own_is_still_redacted() {
        let line = "QUJD".repeat(16);
        let call = |digits: usize, a: &str| {
            format!(
                "data: {{\"id\":\"chatcmpl-{}\",\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":{}}}}}]}}}}]}}\n\n",
                "0".repeat(digits),
                q(a)
            )
        };
        type Event = Box<dyn Fn(usize, &str) -> String>;
        let shapes: [(Event, &[&str], &str); 3] = [
            (Box::new(chat_with_id_of), &["\r", "\n"], "\n"),
            (Box::new(chat_with_id_of), &[" ", "\n"], "\n"),
            (Box::new(call), &["\\n"], "\\n"),
        ];
        let mut redacted = [0; 3];
        for digits in [0, 10, 25, 50, 100, 150, 200, 250, 300, 350, 400] {
            for (s, (event, after, nl)) in shapes.iter().enumerate() {
                let mut events = vec![event(
                    digits,
                    &format!("{{\"k\":\"-----BEGIN PRIVATE KEY-----{nl}"),
                )];
                for _ in 0..60 {
                    events.push(event(digits, &line));
                    events.extend(after.iter().map(|w| event(digits, w)));
                }
                events.push(event(digits, "-----END PRIVATE KEY----- that is all.\"}"));
                events.push(DONE.to_string());
                let p = DirectionPolicy {
                    max_scan_bytes: 4096,
                    ..policy(Verdict::Redact)
                };
                let (out, i) = run(&p, &events);
                let text = client_texts(&out).concat();
                if text.contains("QUJD") {
                    // A line itself went early: that one must block.
                    assert!(i.report().redaction_incomplete, "{digits}: {text}");
                    continue;
                }
                assert!(text.contains("that is all."), "{digits} {after:?}: {text}");
                assert_eq!(i.report().verdict, Verdict::Redact, "{digits} {after:?}");
                redacted[s] += 1;
            }
        }
        assert!(redacted.iter().all(|&n| n > 1), "{redacted:?}");
    }

    #[test]
    fn content_end_skips_plain_and_escaped_trailing_whitespace() {
        assert_eq!(content_end("ab \r\n"), 2);
        assert_eq!(content_end("ab\\n"), 2);
        assert_eq!(content_end("ab\\\\n \\u000a\\t"), 2);
        assert_eq!(content_end(" \n"), 0);
        assert_eq!(content_end("\\n"), 0);
        // Only an escape counts: a plain `n` ending a word is content.
        assert_eq!(content_end("ab n"), 4);
        assert_eq!(content_end("an"), 2);
    }

    /// A token two rules match (`anthropic_key`, then `bearer` once it is
    /// long enough): what went early after the first rule cut it gave
    /// nothing away, so the second rule's later report doesn't block.
    #[test]
    fn a_token_cut_by_one_rule_and_sent_does_not_block_another() {
        let token = format!(
            "sk-ant-api03-{}",
            &"Qm7Zx2Lk9Vb4Nc8Rt1Hy6Jd3Fg5Sa0Wp".repeat(3)[..60]
        );
        let mut redacted = 0;
        for digits in (0..=600).step_by(25) {
            let mut events = vec![chat_with_id_of(digits, "Use Bearer ")];
            events.extend(
                token
                    .chars()
                    .map(|c| chat_with_id_of(digits, &c.to_string())),
            );
            events.push(chat_with_id_of(digits, " that is all."));
            events.push(DONE.to_string());
            let p = DirectionPolicy {
                max_scan_bytes: 4096,
                ..policy(Verdict::Redact)
            };
            let (out, i) = run(&p, &events);
            let text = client_texts(&out).concat();
            if text.starts_with("Use Bearer [REDACTED:dlp]") {
                assert!(text.ends_with(" that is all."), "{digits}: {text}");
                assert_eq!(i.report().verdict, Verdict::Redact, "{digits}");
                redacted += 1;
            } else {
                // The token's start went before any rule matched it.
                assert!(i.report().redaction_incomplete, "{digits}: {text}");
            }
        }
        assert!(redacted > 0);
    }

    /// Many redacted matches in one field cost little to release: finding
    /// where its sent text ends walks its cuts once (AGENT-330).
    #[test]
    fn dense_redactions_in_one_field_release_in_linear_time() {
        let canary = "CANARY42";
        let scanner: Arc<dyn Scanner> =
            Arc::new(super::super::literal::Literal::new(canary).unwrap());
        let p = DirectionPolicy {
            scanners: vec![scanner],
            ..policy(Verdict::Redact)
        };
        let events = [
            chat(&format!("{canary} ").repeat(115_000)),
            DONE.to_string(),
        ];
        let started = std::time::Instant::now();
        let (out, i) = run(&p, &events);
        // The quadratic walk took about 17 s; linear, about 2 s under load.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert!(!out.contains(canary));
        assert_eq!(i.report().verdict, Verdict::Redact);
    }

    #[test]
    fn sent_end_moves_back_only_over_cut_text() {
        let cut = |a, b| (a, b, None);
        assert_eq!(sent_end("AAA b CCC", &vec![cut(6, 9), cut(0, 3)]), 5);
        assert_eq!(sent_end("abKEYcd", &vec![cut(2, 5)]), 7);
        assert_eq!(sent_end("abKEY  ", &vec![cut(2, 5)]), 2);
        assert_eq!(sent_end("KEY KEY ", &vec![cut(4, 7), cut(0, 3)]), 0);
        assert_eq!(sent_end("aKEYKEY", &vec![cut(1, 4), cut(3, 7)]), 1);
    }

    /// AGENT-315: under `flag`, where nothing is held, a full window keeps
    /// scanning in batches rather than taking the whole cap per delta.
    #[test]
    fn a_full_window_under_flag_scans_in_linear_time() {
        let cap = 1 << 16;
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let p = DirectionPolicy {
            scanners: vec![Arc::new(Counting(count.clone()))],
            max_scan_bytes: cap,
            ..policy(Verdict::Flag)
        };
        let mut events: Vec<String> = (0..(cap + cap / 2) / 4096)
            .map(|_| chat(&" ".repeat(4096)))
            .collect();
        let n = 20_000;
        events.extend((0..n).map(|_| chat("a")));
        events.push(DONE.to_string());
        let (out, i) = run(&p, &events);
        assert_eq!(out, events.concat());
        assert!(i.hold_overflowed());
        let scanned = count.load(std::sync::atomic::Ordering::Relaxed);
        let text = n + cap + cap / 2;
        assert!(scanned < 20 * text, "{} per byte", scanned / text);
    }

    /// A scanner that does not take part in streams (a sidecar).
    struct Whole;
    impl Scanner for Whole {
        fn id(&self) -> &str {
            "sidecar:x"
        }
        fn max_match_len(&self) -> usize {
            0
        }
        fn streams(&self) -> bool {
            false
        }
        fn scan(
            &self,
            _: &str,
            _: Direction,
        ) -> Result<Vec<super::super::Hit>, super::super::ScanError> {
            Ok(Vec::new())
        }
    }

    /// A streaming scanner whose every scan fails.
    struct Failing;
    impl Scanner for Failing {
        fn id(&self) -> &str {
            "failing"
        }
        fn max_match_len(&self) -> usize {
            8
        }
        fn scan(
            &self,
            _: &str,
            _: Direction,
        ) -> Result<Vec<super::super::Hit>, super::super::ScanError> {
            Err(super::super::ScanError("failing: broke".into()))
        }
    }

    /// AGENT-278: under fail_open the first error stays on the report, so
    /// a later scan error does not hide that a sidecar never ran.
    #[test]
    fn the_first_stream_error_is_kept() {
        let p = DirectionPolicy {
            scanners: vec![Arc::new(Whole), Arc::new(Failing)],
            on_error: OnError::FailOpen,
            ..policy(Verdict::Redact)
        };
        let (out, i) = run(&p, &[chat("hello there"), DONE.to_string()]);
        assert!(out.contains("hello there"), "{out}");
        let error = i.report().error.clone().unwrap_or_default();
        assert!(error.contains("sidecar:x"), "{error}");
    }

    #[test]
    fn a_scanner_that_skips_streams_follows_on_error() {
        let with = |on_error| DirectionPolicy {
            scanners: vec![Arc::new(Dlp), Arc::new(Whole)],
            on_error,
            ..policy(Verdict::Redact)
        };
        let (out, i) = run(
            &with(OnError::FailClosed),
            &[chat("hello"), DONE.to_string()],
        );
        assert!(out.contains("inspection_blocked"), "{out}");
        assert!(
            i.report()
                .error
                .as_deref()
                .unwrap_or("")
                .contains("sidecar:x")
        );
        let (out, i) = run(&with(OnError::FailOpen), &[chat("hello"), DONE.to_string()]);
        assert!(
            out.contains("hello") && !out.contains("inspection_blocked"),
            "{out}"
        );
        assert!(
            i.report()
                .error
                .as_deref()
                .unwrap_or("")
                .contains("sidecar:x")
        );
    }

    #[test]
    fn a_repeated_key_fails_closed() {
        let event = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\",\"content\":\"b\"}}]}\n\n";
        let (out, i) = run(
            &closed(1 << 20, Verdict::Redact),
            &[event.to_string(), DONE.to_string()],
        );
        assert!(out.contains("inspection_blocked"), "{out}");
        assert!(i.report().error.is_some());
    }

    /// Cost per event and time to first forwarded byte, for the design
    /// doc. Run: `cargo test --release --lib measure_stream -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn measure_stream_cost() {
        let words: Vec<String> = (0..2000).map(|i| chat(&format!("word{i} "))).collect();
        for (label, verdict) in [("flag", Verdict::Flag), ("redact", Verdict::Redact)] {
            let mut i = StreamInspector::new(&policy(verdict));
            let started = std::time::Instant::now();
            let mut first: Option<(usize, std::time::Duration)> = None;
            for (n, e) in words.iter().enumerate() {
                if !i.push(e.as_bytes()).out.is_empty() && first.is_none() {
                    first = Some((n, started.elapsed()));
                }
            }
            i.finish();
            let total = started.elapsed();
            let (n, at) = first.unwrap_or((words.len(), total));
            eprintln!(
                "MEASURE {label}: {:.1} us/event over {} events; first byte after event {n} ({at:?})",
                total.as_secs_f64() * 1e6 / words.len() as f64,
                words.len()
            );
        }
    }
}
