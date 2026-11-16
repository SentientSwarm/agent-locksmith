//! AGENT-265 — inspecting a server-sent event stream as it passes.
//!
//! Events are parsed as they arrive and their text fields fed, in order,
//! to one [`TextWindow`]. Under `pass` or `flag` every event is forwarded
//! the moment it is complete; hits are only audited. Under `redact` or
//! `block` an event is held until no future match can reach back into its
//! text (its text ends before the window's `base`), so a secret split
//! across many deltas is caught before any part of it is sent. A redact
//! rewrites the held events' text fields (the marker in the event where
//! the match starts, the rest removed); a block drops what is held, sends
//! one protocol-shaped error event, and ends the stream. Every string in
//! an event's JSON (aggregates as well as deltas) is scanned.
//!
//! An event longer than `max_scan_bytes`, or held text or events past it,
//! can't be judged in bounds: under `fail_closed` the stream is blocked;
//! under `fail_open` the oldest held event is released early, or (an
//! oversized event) the rest of the stream passes through unscanned.

use super::sse::{self, Protocol, SseEvent, SseParser, TextSpan};
use super::window::{TextWindow, WindowHit};
use super::{Direction, DirectionPolicy, HitRecord, MAX_AUDITED_HITS, OnError, Report, Verdict};
use std::collections::{HashSet, VecDeque};

/// What to send the agent after one push, and whether the stream is over.
#[derive(Debug, Default)]
pub struct Step {
    pub out: Vec<Vec<u8>>,
    pub ended: bool,
}

/// Byte ranges of one text field to cut, with the marker to leave at a
/// cut where a match starts.
type Cuts = Vec<(usize, usize, Option<String>)>;

struct Held {
    event: SseEvent,
    /// Each text field with its absolute start in the stream's text.
    spans: Vec<(TextSpan, usize)>,
    cuts: Vec<Cuts>,
    /// Stream text offset at the end of this event.
    pos: usize,
}

pub struct StreamInspector {
    parser: SseParser,
    window: TextWindow,
    on_hit: Verdict,
    on_error: OnError,
    hold: bool,
    held: VecDeque<Held>,
    held_bytes: usize,
    max_held: usize,
    protocol: Protocol,
    report: Report,
    seen: HashSet<(String, String, String)>,
    /// Where each recorded hit lies, parallel to `report.hits`.
    recorded: Vec<(usize, usize, bool)>,
    ended: bool,
    hold_overflowed: bool,
    /// Past an oversized event under `fail_open`: forward bytes as is.
    passthrough: bool,
}

impl StreamInspector {
    pub fn new(policy: &DirectionPolicy) -> Self {
        Self {
            parser: SseParser::with_cap(policy.max_scan_bytes),
            window: TextWindow::new(policy.scanners.clone(), policy.max_scan_bytes),
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
        }
    }

    pub fn report(&self) -> &Report {
        &self.report
    }

    /// The window or the held events overflowed their cap at least once.
    pub fn hold_overflowed(&self) -> bool {
        self.hold_overflowed || self.window.overflowed()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Step {
        let mut step = Step::default();
        if self.ended {
            step.ended = true;
            return step;
        }
        if self.passthrough {
            step.out.push(chunk.to_vec());
            return step;
        }
        for event in self.parser.push(chunk) {
            self.event(event, &mut step);
            if step.ended {
                self.ended = true;
                return step;
            }
        }
        if self.parser.overflowed() {
            self.oversized_event(&mut step);
        }
        step
    }

    /// An event too long to judge within `max_scan_bytes`.
    fn oversized_event(&mut self, step: &mut Step) {
        self.report.skipped = Some(super::SkipReason::Oversize);
        if self.on_error == OnError::FailClosed {
            self.block(step);
            self.ended = true;
            return;
        }
        while let Some(h) = self.held.pop_front() {
            step.out.push(render(&h));
        }
        if let Some(rest) = self.parser.finish() {
            step.out.push(rest);
        }
        self.passthrough = true;
    }

    /// The upstream ended: send everything still held.
    pub fn finish(&mut self) -> Step {
        let mut step = Step::default();
        if self.ended {
            step.ended = true;
            return step;
        }
        if !self.passthrough {
            // An unterminated last event is still an event: judge it.
            if let Some(rest) = self.parser.finish() {
                self.event(sse::parse(rest), &mut step);
                if step.ended {
                    self.ended = true;
                    return step;
                }
            }
        }
        while let Some(h) = self.held.pop_front() {
            step.out.push(render(&h));
        }
        self.ended = true;
        step.ended = true;
        step
    }

    fn event(&mut self, event: SseEvent, step: &mut Step) {
        if let Some(p) = sse::protocol(&event) {
            self.protocol = p;
        }
        let mut spans = Vec::new();
        let mut hits = Vec::new();
        for span in sse::extract(&event) {
            let start = self.window.end();
            match self.window.push(&span.text) {
                Ok(found) => hits.extend(found),
                Err(e) => {
                    self.report.error = Some(e.0);
                    if self.on_error == OnError::FailClosed {
                        return self.block(step);
                    }
                }
            }
            if self.window.overflowed() && self.on_error == OnError::FailClosed {
                self.report.error = Some("stream text held past max_scan_bytes".into());
                return self.block(step);
            }
            spans.push((span, start));
        }
        let verdict = self.record(&hits);
        if verdict == Verdict::Block {
            return self.block(step);
        }
        if !self.hold {
            step.out.push(event.raw);
            return;
        }
        self.held_bytes += event.raw.len();
        let cuts = vec![Cuts::new(); spans.len()];
        self.held.push_back(Held {
            event,
            spans,
            cuts,
            pos: self.window.end(),
        });
        if verdict == Verdict::Redact {
            let redact: Vec<&WindowHit> = hits
                .iter()
                .filter(|h| self.verdict_of(h) == Verdict::Redact)
                .collect();
            for hit in redact {
                self.cut(hit);
            }
        }
        self.release(step);
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
    fn record(&mut self, hits: &[WindowHit]) -> Verdict {
        let mut verdict = Verdict::Pass;
        for hit in hits {
            let v = self.verdict_of(hit);
            verdict = verdict.max(v);
            if !hit.flag_only {
                self.drop_superseded(hit);
            } else if self
                .recorded
                .iter()
                .any(|&(a, b, _)| a < hit.end && hit.start < b)
            {
                continue;
            }
            let key = (hit.scanner.clone(), hit.rule.clone(), hit.sha256.clone());
            if hit.new && self.seen.insert(key) {
                self.report.verdict = self.report.verdict.max(v);
                if self.report.hits.len() < MAX_AUDITED_HITS {
                    self.report.hits.push(HitRecord {
                        scanner: hit.scanner.clone(),
                        rule: hit.rule.clone(),
                        sha256: hit.sha256.clone(),
                    });
                    self.recorded.push((hit.start, hit.end, hit.flag_only));
                } else {
                    self.report.dropped_hits += 1;
                }
            }
        }
        verdict
    }

    fn drop_superseded(&mut self, hit: &WindowHit) {
        let mut i = 0;
        while i < self.recorded.len() {
            let (a, b, flag_only) = self.recorded[i];
            if flag_only && a < hit.end && hit.start < b {
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

    /// Mark `hit`'s span for removal in every held event it covers.
    fn cut(&mut self, hit: &WindowHit) {
        let marker = hit.new.then(|| format!("[REDACTED:{}]", hit.scanner));
        for held in &mut self.held {
            for (i, (span, a)) in held.spans.iter().enumerate() {
                let b = a + span.text.len();
                if hit.start < b && *a < hit.end {
                    let first = (*a..b).contains(&hit.start);
                    let local = (hit.start.max(*a) - a, hit.end.min(b) - a);
                    held.cuts[i].push((local.0, local.1, marker.clone().filter(|_| first)));
                }
            }
        }
    }

    /// Send held events no future match can reach, oldest first.
    fn release(&mut self, step: &mut Step) {
        while let Some(front) = self.held.front() {
            let safe = front.pos <= self.window.base();
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
            self.held_bytes -= h.event.raw.len();
            step.out.push(render(&h));
        }
    }
}

/// The event as it goes out: untouched unless a field has cuts.
fn render(h: &Held) -> Vec<u8> {
    if h.cuts.iter().all(Vec::is_empty) {
        return h.event.raw.clone();
    }
    let edits: Vec<(String, String)> = h
        .spans
        .iter()
        .zip(&h.cuts)
        .filter(|(_, cuts)| !cuts.is_empty())
        .map(|((span, _), cuts)| (span.pointer.clone(), apply_cuts(&span.text, cuts)))
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
    fn split_secret_redacted_before_forwarding() {
        let k = key();
        for (event, tail) in [
            (chat as fn(&str) -> String, DONE),
            (responses, DONE),
            (anthropic, PING),
        ] {
            let (out, i) = run(&policy(Verdict::Redact), &stream(event, tail));
            for start in 0..=k.len() - 8 {
                assert!(
                    !out.contains(&k[start..start + 8]),
                    "leaked {:?} in {out}",
                    &k[start..start + 8]
                );
            }
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
