//! Per-tool response controls (M7 / C-17, SPEC §4.7.7).
//!
//! Three orthogonal controls applied to each upstream response:
//!  1. **Total size cap** (`max_size_bytes`): bounds how many bytes
//!     Locksmith will accept from the upstream. Applies to both
//!     non-streaming and streaming flows. Streaming uses a byte-counter
//!     adapter (`SizeCappedStream`) that emits a truncation marker and
//!     stops after the cap is reached; non-streaming returns 502 with
//!     a `response_size_exceeded` audit row.
//!  2. **Content-type allowlist**: the upstream's `Content-Type` header
//!     (less the `; charset=...` suffix) must match one of the
//!     configured strings exactly. Absent ⇒ no filter. Streaming
//!     paths can use this too, but enforcement is at the response
//!     header — no per-chunk inspection.
//!  3. **Regex redaction** (`redaction_patterns`): replaces matches in
//!     non-streaming response bodies with a marker. Streaming bypasses
//!     redaction (D-18: composes with LlamaFirewall and similar
//!     in-process scanners which target the streaming chunks
//!     directly). Audit records the pattern id, match count, and a
//!     SHA-256 hash of the cleartext — never the cleartext itself.

use crate::config::{RedactionPatternConfig, ResponseControlsConfig};
use regex::Regex;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum ApplyOutcome {
    Allowed {
        body: Vec<u8>,
        redactions: Vec<RedactionRecord>,
    },
    SizeExceeded {
        observed: usize,
        cap: u64,
    },
    ContentTypeDisallowed {
        observed: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionRecord {
    pub pattern_id: String,
    pub matches: usize,
    pub match_hash: String,
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    id: String,
    regex: Regex,
    replacement: String,
}

#[derive(Debug, Clone, Default)]
pub struct ResponseControls {
    max_size_bytes: Option<u64>,
    content_type_allowlist: Option<Vec<String>>,
    patterns: Vec<CompiledPattern>,
}

impl ResponseControls {
    /// Compile a config block into the runtime form. Errors here
    /// surface from `parse_config_str` at startup; the proxy hot path
    /// only sees pre-compiled regexes.
    pub fn compile(cfg: &ResponseControlsConfig) -> Result<Self, regex::Error> {
        let mut patterns = Vec::with_capacity(cfg.redaction_patterns.len());
        for p in &cfg.redaction_patterns {
            patterns.push(compile_pattern(p)?);
        }
        Ok(Self {
            max_size_bytes: cfg.max_size_bytes,
            content_type_allowlist: cfg.content_type_allowlist.clone(),
            patterns,
        })
    }

    pub fn max_size_bytes(&self) -> Option<u64> {
        self.max_size_bytes
    }

    /// Apply all three controls to a non-streaming response.
    pub fn apply_non_streaming(&self, content_type: Option<&str>, body: Vec<u8>) -> ApplyOutcome {
        if let Some(cap) = self.max_size_bytes
            && body.len() as u64 > cap
        {
            return ApplyOutcome::SizeExceeded {
                observed: body.len(),
                cap,
            };
        }
        if let Some(allow) = &self.content_type_allowlist {
            let observed_full = content_type.unwrap_or("");
            let observed = observed_full
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let allowed = allow.iter().any(|a| a.eq_ignore_ascii_case(&observed));
            if !allowed {
                return ApplyOutcome::ContentTypeDisallowed {
                    observed: observed_full.to_string(),
                };
            }
        }
        if self.patterns.is_empty() {
            return ApplyOutcome::Allowed {
                body,
                redactions: Vec::new(),
            };
        }
        let Ok(text) = std::str::from_utf8(&body) else {
            return ApplyOutcome::Allowed {
                body,
                redactions: Vec::new(),
            };
        };
        let mut working = text.to_string();
        let mut records = Vec::new();
        for pattern in &self.patterns {
            let mut hasher = Sha256::new();
            let mut matches = 0;
            for m in pattern.regex.find_iter(&working) {
                hasher.update(m.as_str().as_bytes());
                matches += 1;
            }
            if matches == 0 {
                continue;
            }
            working = pattern
                .regex
                .replace_all(&working, pattern.replacement.as_str())
                .into_owned();
            records.push(RedactionRecord {
                pattern_id: pattern.id.clone(),
                matches,
                match_hash: hex_sha256(hasher.finalize().as_slice()),
            });
        }
        ApplyOutcome::Allowed {
            body: working.into_bytes(),
            redactions: records,
        }
    }

    /// Streaming-side helpers — the proxy uses these on the streaming
    /// branch instead of `apply_non_streaming` (R-N6 doesn't tolerate
    /// per-chunk regex; T7.3 wraps the body stream with a size-counting
    /// adapter).
    pub fn streaming_size_cap(&self) -> Option<u64> {
        self.max_size_bytes
    }

    /// Does this tool have any redaction patterns? Proxy hot path
    /// uses this to decide between streaming (no patterns) and
    /// buffered apply (patterns present). Redaction is non-streaming-
    /// only per SPEC.
    pub fn has_redaction_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }

    pub fn streaming_content_type_allowed(&self, content_type: Option<&str>) -> bool {
        let Some(allow) = &self.content_type_allowlist else {
            return true;
        };
        let observed_full = content_type.unwrap_or("");
        let observed = observed_full
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        allow.iter().any(|a| a.eq_ignore_ascii_case(&observed))
    }
}

fn compile_pattern(p: &RedactionPatternConfig) -> Result<CompiledPattern, regex::Error> {
    let regex = Regex::new(&p.regex)?;
    let replacement = p
        .replacement
        .clone()
        .unwrap_or_else(|| format!("[REDACTED:{}]", p.id));
    Ok(CompiledPattern {
        id: p.id.clone(),
        regex,
        replacement,
    })
}

fn hex_sha256(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── Streaming wrapper (T7.3) ───────────────────────────────────────

use bytes::Bytes;
use futures_util::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Marker injected at the end of a truncated stream so the agent can
/// distinguish "upstream finished" from "Locksmith capped it." Encoded
/// as a JSON line on its own — agents that aren't expecting it ignore
/// it; agents that are expecting it parse the cap event.
pub const STREAM_TRUNCATION_MARKER: &str = "\n{\"_locksmith\":\"response_size_exceeded\"}\n";

/// Stream adapter that counts bytes and truncates at `cap`. On the
/// chunk that crosses the cap, the trailing slice is dropped and a
/// truncation marker is appended; subsequent polls return None.
///
/// Shape:
///   - `cap = None` ⇒ pure passthrough (zero overhead).
///   - `cap = Some(n)` ⇒ counts every yielded byte; on overflow,
///     emits the prefix that fits + the marker, then signals the
///     `truncated` callback (T7.4 audit hook).
pub struct SizeCappedStream<S, F> {
    inner: S,
    cap: Option<u64>,
    seen: u64,
    truncated: bool,
    /// Pending marker yield — returned on the poll AFTER the truncated
    /// chunk so the agent observes prefix + marker in order.
    pending_marker: Option<Bytes>,
    /// Called exactly once when truncation fires. Used by the proxy
    /// to write the `response_size_exceeded` audit row.
    on_truncate: Option<F>,
}

impl<S, F> SizeCappedStream<S, F>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
    F: FnOnce(u64),
{
    pub fn new(inner: S, cap: Option<u64>, on_truncate: F) -> Self {
        Self {
            inner,
            cap,
            seen: 0,
            truncated: false,
            pending_marker: None,
            on_truncate: Some(on_truncate),
        }
    }

    fn fire_truncation(&mut self, prefix: Bytes) -> Bytes {
        self.truncated = true;
        if let Some(cb) = self.on_truncate.take() {
            cb(self.seen);
        }
        self.pending_marker = Some(Bytes::from(STREAM_TRUNCATION_MARKER));
        prefix
    }
}

impl<S, F> Stream for SizeCappedStream<S, F>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
    F: FnOnce(u64) + Unpin,
{
    type Item = Result<Bytes, reqwest::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Yield the marker if we have one queued.
        if let Some(m) = this.pending_marker.take() {
            return Poll::Ready(Some(Ok(m)));
        }
        if this.truncated {
            return Poll::Ready(None);
        }

        // No cap configured ⇒ passthrough.
        let Some(cap) = this.cap else {
            return Pin::new(&mut this.inner).poll_next(cx);
        };

        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok(chunk))) => {
                let new_total = this.seen.saturating_add(chunk.len() as u64);
                if new_total <= cap {
                    this.seen = new_total;
                    Poll::Ready(Some(Ok(chunk)))
                } else {
                    // Truncate this chunk. Trim to the slice that
                    // exactly fills the cap; the rest is dropped.
                    let allowed = cap.saturating_sub(this.seen) as usize;
                    let prefix = chunk.slice(..allowed);
                    this.seen = cap;
                    let yielded = this.fire_truncation(prefix.clone());
                    Poll::Ready(Some(Ok(yielded)))
                }
            }
        }
    }
}
