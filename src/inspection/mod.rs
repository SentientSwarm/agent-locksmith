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
mod literal;
mod text;

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

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
    fn max_match_len(&self) -> usize;
    fn scan(&self, text: &str, direction: Direction) -> Result<Vec<Hit>, ScanError>;
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

/// What one inspection found, for the audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub direction: Direction,
    pub verdict: Verdict,
    pub hits: Vec<HitRecord>,
    pub skipped: Option<SkipReason>,
    pub error: Option<String>,
}

impl Report {
    fn new(direction: Direction) -> Self {
        Self {
            direction,
            verdict: Verdict::Pass,
            hits: Vec::new(),
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
    let mut report = Report::new(direction);
    if body.len() > policy.max_scan_bytes {
        report.skipped = Some(SkipReason::Oversize);
        return unjudged(policy, report);
    }
    // A compressed body can't be scanned as sent. Unlike plain binary it
    // can hide text, so it follows `on_error` rather than passing.
    if meta.encoded {
        report.skipped = Some(SkipReason::Encoded);
        return unjudged(policy, report);
    }
    let content_type = meta.content_type;
    // Binary bodies are not text the scanners understand; they pass
    // (audited) whatever `on_error` says, so uploads are never blocked.
    let Ok(doc) = text::Document::parse(content_type, body) else {
        report.skipped = Some(SkipReason::NotText);
        return Outcome::Forward { body: None, report };
    };
    let segments = doc.segments();
    let mut spans: HashMap<usize, Vec<(usize, usize, String)>> = HashMap::new();
    for (index, segment) in segments.iter().enumerate() {
        for scanner in &policy.scanners {
            match scanner.scan(segment, direction) {
                Ok(hits) => {
                    for hit in hits {
                        let Some(matched) = segment.get(hit.start..hit.end) else {
                            continue;
                        };
                        let verdict = if hit.flag_only {
                            policy.on_hit.min(Verdict::Flag)
                        } else {
                            policy.on_hit
                        };
                        report.verdict = report.verdict.max(verdict);
                        report.hits.push(HitRecord {
                            scanner: scanner.id().to_string(),
                            rule: hit.rule.clone(),
                            sha256: sha256_hex(matched),
                        });
                        if verdict == Verdict::Redact || verdict == Verdict::Block {
                            spans.entry(index).or_default().push((
                                hit.start,
                                hit.end,
                                scanner.id().to_string(),
                            ));
                        }
                    }
                }
                Err(e) => report.error = Some(format!("{}: {e}", scanner.id())),
            }
        }
    }
    if report.error.is_some() && policy.on_error == OnError::FailClosed {
        return unjudged(policy, report);
    }
    match report.verdict {
        Verdict::Block => Outcome::Block { report },
        Verdict::Redact => Outcome::Forward {
            body: Some(doc.redact(&spans)),
            report,
        },
        Verdict::Pass | Verdict::Flag => Outcome::Forward { body: None, report },
    }
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
}
