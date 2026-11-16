//! AGENT-262 / D-18 (AGENT-150) — content inspection on the proxy path.
//!
//! A route's policy names scanners for each direction. Request scanners
//! see the body Locksmith already buffers before anything reaches the
//! upstream; response scanners see a buffered (non-streamed) body before
//! anything reaches the agent. Every scanner reports [`Hit`]s; the policy
//! turns them into one [`Verdict`]. Audit records rule ids and a SHA-256
//! of each matched span, never the text (the `response_controls` rule).
//!
//! See `docs/development/inspection.md`.

pub mod config;
pub(crate) mod dlp;
mod injection;
pub mod lanes;
mod literal;
mod normalize;
pub mod sidecar;
pub mod sse;
pub mod stream;
mod text;
pub mod window;

pub(crate) use text::{percent_decode, percent_decode_path};

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

thread_local! {
    static SCAN_DEADLINE: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
}

/// AGENT-276 — run `f` with one deadline shared by every scanner call made
/// inside it on this thread. Out-of-process scanners make no call once it
/// has passed, so a body with many strings cannot outlive its scan.
pub fn with_deadline<R>(deadline: std::time::Instant, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<std::time::Instant>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SCAN_DEADLINE.with(|d| d.set(self.0));
        }
    }
    let _restore = Restore(SCAN_DEADLINE.with(|d| d.replace(Some(deadline))));
    f()
}

/// The deadline set by [`with_deadline`] on this thread, if any.
pub fn scan_deadline() -> Option<std::time::Instant> {
    SCAN_DEADLINE.with(|d| d.get())
}

pub use config::InspectionConfig;

/// Which way the inspected bytes travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

/// What happens to a body with hits. Ordered by severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Flag,
    Redact,
    Block,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Flag => "flag",
            Verdict::Redact => "redact",
            Verdict::Block => "block",
        }
    }
}

/// What happens when a scanner cannot give an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    FailOpen,
    FailClosed,
}

/// One match: a rule and the byte span of the scanned text it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: String,
    pub start: usize,
    pub end: usize,
    /// Rules too noisy to act on (an entropy heuristic) only ever flag.
    pub flag_only: bool,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct ScanError(pub String);

/// A content check. Scanners are pure over the text they are given.
pub trait Scanner: Send + Sync {
    fn id(&self) -> &str;
    /// Upper bound on the length (in bytes) of anything this scanner can
    /// match. Streaming scanning keeps this much overlap between windows.
    /// A scanner that folds its input (`injection`) bounds the folded
    /// text; its window must carry that much folded text.
    fn max_match_len(&self) -> usize;
    fn scan(&self, text: &str, direction: Direction) -> Result<Vec<Hit>, ScanError>;
    /// Does this scanner take part in streamed-response windows? A
    /// classifier that scores whole texts (a sidecar) does not.
    fn streams(&self) -> bool {
        true
    }
}

/// The compiled policy for one direction of one route.
pub struct DirectionPolicy {
    pub scanners: Vec<Arc<dyn Scanner>>,
    pub on_hit: Verdict,
    pub on_error: OnError,
    pub max_scan_bytes: usize,
}

impl DirectionPolicy {
    /// Longest match any of this policy's scanners can report.
    pub fn max_match_len(&self) -> usize {
        self.scanners
            .iter()
            .map(|s| s.max_match_len())
            .max()
            .unwrap_or(0)
    }
}

#[derive(Default)]
pub struct RoutePolicy {
    pub request: Option<DirectionPolicy>,
    pub response: Option<DirectionPolicy>,
}

/// Every route's compiled policy, built once at startup.
#[derive(Default)]
pub struct Inspection {
    routes: HashMap<String, RoutePolicy>,
}

impl Inspection {
    pub fn policy(&self, route: &str) -> Option<&RoutePolicy> {
        self.routes.get(route)
    }
}

/// An audited hit: never the matched text, only its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HitRecord {
    pub scanner: String,
    pub rule: String,
    pub sha256: String,
}

/// Why a body was not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Oversize,
    NotText,
    Streaming,
    /// Compressed or otherwise content-encoded: not scannable as sent.
    Encoded,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::Oversize => "oversize",
            SkipReason::NotText => "not_text",
            SkipReason::Streaming => "streaming",
            SkipReason::Encoded => "encoded",
        }
    }
}

/// Most hits one audit row lists; the rest are only counted.
pub const MAX_AUDITED_HITS: usize = 64;

/// What one inspection found, for the audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub direction: Direction,
    pub verdict: Verdict,
    pub hits: Vec<HitRecord>,
    /// Distinct hits past `MAX_AUDITED_HITS`, counted but not listed.
    pub dropped_hits: usize,
    pub skipped: Option<SkipReason>,
    pub error: Option<String>,
}

impl Report {
    fn new(direction: Direction) -> Self {
        Self {
            direction,
            verdict: Verdict::Pass,
            hits: Vec::new(),
            dropped_hits: 0,
            skipped: None,
            error: None,
        }
    }

    /// Nothing to audit: scanned cleanly with no hits.
    pub fn is_quiet(&self) -> bool {
        self.hits.is_empty() && self.skipped.is_none() && self.error.is_none()
    }
}

pub enum Outcome {
    /// Forward the body: `Some` is the rewritten (redacted) body.
    Forward {
        body: Option<Vec<u8>>,
        report: Report,
    },
    Block {
        report: Report,
    },
}

/// The outcome for a scan that did not finish (`why`: timed out, failed).
pub fn unfinished(policy: &DirectionPolicy, direction: Direction, why: &str) -> Outcome {
    let mut report = Report::new(direction);
    report.error = Some(format!("scan {why}"));
    unjudged(policy, report)
}

impl DirectionPolicy {
    /// A policy with no scanners that fails closed: the fallback when a
    /// route's policy can't be found for a scan that failed.
    pub fn closed() -> Self {
        Self {
            scanners: Vec::new(),
            on_hit: Verdict::Block,
            on_error: OnError::FailClosed,
            max_scan_bytes: 0,
        }
    }
}

/// Fail closed or open on a body the scanners could not judge.
fn unjudged(policy: &DirectionPolicy, report: Report) -> Outcome {
    match policy.on_error {
        OnError::FailClosed => Outcome::Block {
            report: Report {
                verdict: Verdict::Block,
                ..report
            },
        },
        OnError::FailOpen => Outcome::Forward { body: None, report },
    }
}

pub(crate) fn sha256_hex(text: &str) -> String {
    hex_lower(&Sha256::digest(text.as_bytes()))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The headers that decide how a body is read.
#[derive(Debug, Clone, Copy, Default)]
pub struct BodyMeta<'a> {
    pub content_type: Option<&'a str>,
    /// Any `Content-Encoding` other than `identity` (or one that could
    /// not be read): the body is not scannable as sent.
    pub encoded: bool,
}

/// Inspect `body` under `policy`.
pub fn apply(
    policy: &DirectionPolicy,
    direction: Direction,
    meta: BodyMeta<'_>,
    body: &[u8],
) -> Outcome {
    apply_with(policy, direction, meta, body, &[])
}

/// Hits found so far, keyed so the raw views don't count a hit twice.
type Seen = HashSet<(String, String, String)>;

/// A span one scanner matched, and whether its hit was new.
struct ScanSpan {
    start: usize,
    end: usize,
    scanner: String,
    verdict: Verdict,
    new: bool,
}

/// Run every scanner over `text`; returns the spans to rewrite.
fn scan_text(
    policy: &DirectionPolicy,
    direction: Direction,
    text: &str,
    report: &mut Report,
    seen: &mut Seen,
) -> Vec<ScanSpan> {
    let mut spans = Vec::new();
    for scanner in &policy.scanners {
        let hits = match scanner.scan(text, direction) {
            Ok(hits) => hits,
            Err(e) => {
                report.error = Some(format!("{}: {e}", scanner.id()));
                continue;
            }
        };
        for hit in hits {
            let Some(matched) = text.get(hit.start..hit.end) else {
                report.error = Some(format!("{}: hit outside the text", scanner.id()));
                continue;
            };
            let verdict = if hit.flag_only {
                policy.on_hit.min(Verdict::Flag)
            } else {
                policy.on_hit
            };
            let sha256 = sha256_hex(matched);
            let key = (scanner.id().to_string(), hit.rule.clone(), sha256.clone());
            let new = seen.insert(key);
            if new {
                report.verdict = report.verdict.max(verdict);
                if report.hits.len() < MAX_AUDITED_HITS {
                    report.hits.push(HitRecord {
                        scanner: scanner.id().to_string(),
                        rule: hit.rule.clone(),
                        sha256,
                    });
                } else {
                    report.dropped_hits += 1;
                }
            }
            spans.push(ScanSpan {
                start: hit.start,
                end: hit.end,
                scanner: scanner.id().to_string(),
                verdict,
                new,
            });
        }
    }
    spans
}

/// Inspect `body`, plus `extra` text that travels with it (a request's
/// decoded path and query), which can be judged but not rewritten.
pub fn apply_with(
    policy: &DirectionPolicy,
    direction: Direction,
    meta: BodyMeta<'_>,
    body: &[u8],
    extra: &[String],
) -> Outcome {
    let mut report = Report::new(direction);
    let mut seen = Seen::new();
    // An oversized body is not read, and a compressed one can't be read
    // as sent (unlike plain binary it can hide text): both follow
    // `on_error`. What travels with it (path, query) is still judged.
    let unreadable = if body.len() > policy.max_scan_bytes {
        Some(SkipReason::Oversize)
    } else if meta.encoded {
        Some(SkipReason::Encoded)
    } else {
        None
    };
    if let Some(reason) = unreadable {
        for view in extra {
            scan_text(policy, direction, view, &mut report, &mut seen);
        }
        if report.verdict >= Verdict::Redact {
            report.verdict = Verdict::Block;
            return Outcome::Block { report };
        }
        report.skipped = Some(reason);
        return unjudged(policy, report);
    }
    let doc = text::Document::parse(meta.content_type, body).ok();
    let mut spans: text::Spans = HashMap::new();
    let segments = doc
        .as_ref()
        .map(text::Document::segments)
        .unwrap_or_default();
    for (index, segment) in segments.iter().enumerate() {
        for f in scan_text(policy, direction, segment, &mut report, &mut seen) {
            if f.verdict >= Verdict::Redact {
                spans
                    .entry(index)
                    .or_default()
                    .push((f.start, f.end, f.scanner));
            }
        }
    }
    // What parsing hides (invalid UTF-8, escapes in unparseable JSON,
    // shadowed duplicate keys, form encoding) and what travels outside
    // the body is judged too.
    let mut views = text::raw_views(meta.content_type, body);
    views.retain(|v| segments.len() != 1 || segments[0] != *v);
    views.extend(extra.iter().cloned());
    // A redact-level hit only these views see can't be rewritten.
    let mut unredactable = false;
    for view in &views {
        let found = scan_text(policy, direction, view, &mut report, &mut seen);
        unredactable |= found.iter().any(|f| f.new && f.verdict >= Verdict::Redact);
    }
    if report.error.is_some() && policy.on_error == OnError::FailClosed {
        return unjudged(policy, report);
    }
    if doc.is_none() && report.hits.is_empty() {
        // Binary with nothing text-shaped in it: forwarded, audited.
        report.skipped = Some(SkipReason::NotText);
    }
    match (report.verdict, doc) {
        (Verdict::Redact, Some(doc)) if !unredactable => {
            // Only what the parser located can be rewritten. A copy left
            // anywhere else (the query, a duplicate key, an encoded form
            // field) means the redaction is incomplete: block instead.
            let rewritten = doc.redact(&spans);
            if leaves_a_hit(policy, direction, meta.content_type, &rewritten, extra) {
                report.verdict = Verdict::Block;
                return Outcome::Block { report };
            }
            Outcome::Forward {
                body: Some(rewritten),
                report,
            }
        }
        (Verdict::Redact | Verdict::Block, _) => {
            report.verdict = Verdict::Block;
            Outcome::Block { report }
        }
        _ => Outcome::Forward { body: None, report },
    }
}

/// Does any non-flag-only hit survive in `body`'s raw views or `extra`?
fn leaves_a_hit(
    policy: &DirectionPolicy,
    direction: Direction,
    content_type: Option<&str>,
    body: &[u8],
    extra: &[String],
) -> bool {
    let mut views = text::raw_views(content_type, body);
    views.extend(extra.iter().cloned());
    views.iter().any(|view| {
        policy.scanners.iter().any(|s| {
            s.scan(view, direction)
                .map_or(true, |hits| hits.iter().any(|h| !h.flag_only))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Failing;
    impl Scanner for Failing {
        fn id(&self) -> &str {
            "failing"
        }
        fn max_match_len(&self) -> usize {
            0
        }
        fn scan(&self, _: &str, _: Direction) -> Result<Vec<Hit>, ScanError> {
            Err(ScanError("unavailable".into()))
        }
    }

    fn policy(on_error: OnError) -> DirectionPolicy {
        DirectionPolicy {
            scanners: vec![Arc::new(Failing)],
            on_hit: Verdict::Block,
            on_error,
            max_scan_bytes: 1024,
        }
    }

    #[test]
    fn scanner_error_follows_on_error() {
        let closed = apply(
            &policy(OnError::FailClosed),
            Direction::Request,
            BodyMeta::default(),
            b"x",
        );
        assert!(matches!(closed, Outcome::Block { report } if report.error.is_some()));
        let open = apply(
            &policy(OnError::FailOpen),
            Direction::Request,
            BodyMeta::default(),
            b"x",
        );
        assert!(
            matches!(open, Outcome::Forward { body: None, report } if report.error.as_deref() == Some("failing: unavailable"))
        );
    }

    #[test]
    fn flag_only_hits_never_block() {
        struct Noisy;
        impl Scanner for Noisy {
            fn id(&self) -> &str {
                "noisy"
            }
            fn max_match_len(&self) -> usize {
                1
            }
            fn scan(&self, _: &str, _: Direction) -> Result<Vec<Hit>, ScanError> {
                Ok(vec![Hit {
                    rule: "entropy".into(),
                    start: 0,
                    end: 1,
                    flag_only: true,
                }])
            }
        }
        let p = DirectionPolicy {
            scanners: vec![Arc::new(Noisy)],
            on_hit: Verdict::Block,
            on_error: OnError::FailClosed,
            max_scan_bytes: 1024,
        };
        let out = apply(&p, Direction::Request, BodyMeta::default(), b"x");
        assert!(matches!(out, Outcome::Forward { report, .. } if report.verdict == Verdict::Flag));
    }

    /// A hit per space-separated word: distinct hits on demand.
    struct Words;
    impl Scanner for Words {
        fn id(&self) -> &str {
            "words"
        }
        fn max_match_len(&self) -> usize {
            16
        }
        fn scan(&self, text: &str, _: Direction) -> Result<Vec<Hit>, ScanError> {
            let mut at = 0;
            Ok(text
                .split(' ')
                .map(|w| {
                    let hit = Hit {
                        rule: "word".into(),
                        start: at,
                        end: at + w.len(),
                        flag_only: false,
                    };
                    at += w.len() + 1;
                    hit
                })
                .filter(|h| h.end > h.start)
                .collect())
        }
    }

    #[test]
    fn audited_hits_are_capped() {
        let p = DirectionPolicy {
            scanners: vec![Arc::new(Words)],
            on_hit: Verdict::Flag,
            on_error: OnError::FailOpen,
            max_scan_bytes: 1 << 20,
        };
        let body: String = (0..500).map(|i| format!("w{i} ")).collect();
        let Outcome::Forward { report, .. } =
            apply(&p, Direction::Request, BodyMeta::default(), body.as_bytes())
        else {
            panic!("flag forwards");
        };
        assert_eq!(report.hits.len(), MAX_AUDITED_HITS);
        assert_eq!(report.dropped_hits, 500 - MAX_AUDITED_HITS);
    }

    #[test]
    fn the_query_is_judged_when_the_body_is_not() {
        let p = DirectionPolicy {
            scanners: vec![Arc::new(Words)],
            on_hit: Verdict::Block,
            on_error: OnError::FailOpen,
            max_scan_bytes: 4,
        };
        let out = apply_with(
            &p,
            Direction::Request,
            BodyMeta::default(),
            b"a long body",
            &["q=x".into()],
        );
        assert!(
            matches!(out, Outcome::Block { .. }),
            "oversize body let the query through"
        );
        let encoded = BodyMeta {
            content_type: None,
            encoded: true,
        };
        let out = apply_with(&p, Direction::Request, encoded, b"ab", &["q=x".into()]);
        assert!(
            matches!(out, Outcome::Block { .. }),
            "encoded body let the query through"
        );
    }
}
