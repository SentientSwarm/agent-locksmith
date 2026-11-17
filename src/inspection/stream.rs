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
use super::window::{TextWindow, WindowHit};
use super::{
    Direction, DirectionPolicy, HitRecord, MAX_AUDITED_HITS, OnError, Report, Scanner, Verdict,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Distinct hits remembered for deduplication; past it, new hits are
/// counted as dropped without being remembered.
const MAX_SEEN: usize = 4 * MAX_AUDITED_HITS;

/// Unfinished outputs given their own window; more share one, so memory
/// is bounded. A finished output's window drops its text.
const MAX_LANES: usize = 32;

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
    /// Short texts scanned alone and found clean.
    clean: HashSet<String>,
    /// A configured scanner can't judge streams and `on_error` is
    /// `fail_closed`: the stream is blocked before anything is sent.
    unjudged: bool,
    /// The protocol scheme the stream's first protocol event named.
    scheme: Option<super::lanes::Scheme>,
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
            clean: HashSet::new(),
            unjudged: false,
            scheme: None,
        }
    }

    pub fn report(&self) -> &Report {
        &self.report
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

    /// The lane `lane`'s index, made on first use. Past `MAX_LANES`
    /// unfinished outputs (or `MAX_OUTPUTS` in all, or lane paths past
    /// `max_scan_bytes`), new outputs share one
    /// window, which can split a match: that is an overflow (`None` under
    /// `fail_closed`).
    fn lane(&mut self, lane: &Lane) -> Option<usize> {
        if let Some(&i) = self.by_lane.get(lane) {
            return Some(i);
        }
        let shared = Lane {
            path: "*".into(),
            tags: Vec::new(),
        };
        let live = self.lanes.iter().filter(|l| !l.done).count();
        let full = live + 1 >= MAX_LANES
            || self.lanes.len() + 1 >= MAX_OUTPUTS
            || self.lane_bytes + lane.path.len() > self.max_held;
        let lane = if full {
            if self.on_error == OnError::FailClosed {
                return None;
            }
            self.hold_overflowed = true;
            &shared
        } else {
            lane
        };
        if let Some(&i) = self.by_lane.get(lane) {
            return Some(i);
        }
        self.lane_bytes += lane.path.len();
        self.lanes.push(LaneState {
            lane: lane.clone(),
            window: TextWindow::new(self.scanners.clone(), self.max_held),
            done: false,
        });
        let i = self.lanes.len() - 1;
        self.by_lane.insert(lane.clone(), i);
        Some(i)
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
        let Some(spans) = sse::extract_within(&event, self.max_held, self.scheme) else {
            return self.oversized(Some(event), step);
        };
        if spans
            .iter()
            .any(|s| s.place == sse::Place::View { json: true })
            && self.on_error == OnError::FailClosed
        {
            self.report.error = Some("stream event data is JSON that does not parse".into());
            return self.block(step);
        }
        if spans.iter().any(|s| s.place == sse::Place::Hidden) {
            // A hidden value is scanned in its event only: one split
            // across events would be missed.
            if self.on_error == OnError::FailClosed {
                self.report.error = Some("stream event repeats a JSON key".into());
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
            let Some(lane) = self.lane(key) else {
                self.report.error = Some("more stream outputs than can be inspected".into());
                return self.block(step);
            };
            let state = &mut self.lanes[lane];
            if state.done {
                // Its output was said to be finished, and its held events
                // may already be out: a match spanning the two is missed.
                if self.on_error == OnError::FailClosed {
                    self.report.error = Some("stream text after its output finished".into());
                    return self.block(step);
                }
                self.hold_overflowed = true;
                state.done = false;
            }
            let start = state.window.end();
            let found = state.window.push(&span.text);
            let overflowed = state.window.overflowed();
            if !self.scanned(lane, found, overflowed, &mut hits, step) {
                return;
            }
            fields.push(Field { span, lane, start });
        }
        if self.over_cap(step) {
            return;
        }
        let closes = sse::closes(&event, self.scheme);
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
            self.cut_all(&hits);
            if self.unrewritable() {
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

    /// Fix the stream's protocol scheme on its first event that names one.
    /// An event naming another (or whose name and `type` disagree) could be
    /// read two ways by clients: false when that blocked the stream.
    fn fix_scheme(&mut self, event: &SseEvent, step: &mut Step) -> bool {
        let found = sse::scheme(event);
        let changed = matches!((self.scheme, found), (Some(a), Some(b)) if a != b);
        if changed || sse::names_disagree(event) || sse::seeds_output(event) {
            if self.on_error == OnError::FailClosed {
                self.report.error = Some(if changed || sse::names_disagree(event) {
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
                self.report.error = Some(e.0);
                if self.on_error == OnError::FailClosed {
                    self.block(step);
                    return false;
                }
            }
        }
        if overflowed && self.on_error == OnError::FailClosed {
            self.report.error = Some("stream text held past max_scan_bytes".into());
            self.block(step);
            return false;
        }
        true
    }

    /// All lanes together hold more text than `max_scan_bytes`.
    fn over_cap(&mut self, step: &mut Step) -> bool {
        let held: usize = self.lanes.iter().map(|l| l.window.held()).sum();
        if held <= self.max_held {
            return false;
        }
        self.hold_overflowed = true;
        if self.on_error == OnError::FailClosed {
            self.report.error = Some("stream text held past max_scan_bytes".into());
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
        let mut hits = Vec::new();
        for lane in 0..self.lanes.len() {
            if !closes.iter().any(|c| c.covers(&self.lanes[lane].lane)) {
                continue;
            }
            let found = self.lanes[lane].window.flush();
            let overflowed = self.lanes[lane].window.overflowed();
            if !self.scanned(lane, found, overflowed, &mut hits, step) {
                return;
            }
            self.lanes[lane].done = true;
            self.lanes[lane].window.release_text();
        }
        let verdict = self.judge(&hits, step);
        if !step.ended && verdict == Verdict::Redact {
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
                lane.done || f.start + f.span.text.len() <= lane.window.base()
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
                self.report.error = Some("stream events held past max_scan_bytes".into());
                return self.block(step);
            }
            self.hold_overflowed |= !safe;
            let h = self.held.pop_front().expect("front exists");
            self.held_bytes -= h.cost;
            step.out.push(render(&h));
        }
    }
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
        let events: Vec<String> = (0..40).map(|n| chat_n(n, "hi ")).collect();
        let (out, _) = run(&closed(1 << 20, Verdict::Redact), &events);
        assert!(out.contains("inspection_blocked"), "{out}");
        let (out, i) = run(&policy(Verdict::Redact), &events);
        assert!(!out.contains("inspection_blocked") && i.hold_overflowed());
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
        }
        for t in 0..10 {
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
        // The key arrives too small to trigger a scan: it is still
        // unscanned when the oversize last event ends the stream.
        let mut out = i.push(chat(&"x ".repeat(500)).as_bytes()).out;
        out.extend(i.push(chat(&key()).as_bytes()).out);
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
