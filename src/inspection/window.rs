//! AGENT-265 — a sliding window over streamed text.
//!
//! Text arrives in pieces (one SSE delta at a time). Each push scans the
//! held text plus the new piece and reports hits that end in the new
//! piece, at absolute offsets in the stream. Afterwards the window drops
//! everything older than the overlap: the shortest tail whose length,
//! raw and folded, is at least the longest match any scanner can report
//! minus one. A match can't start before that tail, so text before
//! `base()` is final. The tail is capped at `cap` raw bytes; past the cap
//! (whitespace or invisible padding that folds to nothing) the window
//! overflows and a match padded that far can be missed.
//!
//! Rescanning the whole tail on every push would cost the tail's length
//! per push, quadratic when padding keeps the tail long. So a push scans
//! only once the unscanned text is at least an eighth of what is held,
//! which keeps the total scanned to a small multiple of the stream;
//! `flush` scans the rest. Text is final only once scanned, so `base`
//! never passes unscanned text.

use super::{Direction, ScanError, Scanner, normalize, sha256_hex};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// A hit at absolute offsets in the stream's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowHit {
    pub scanner: String,
    pub rule: String,
    pub start: usize,
    pub end: usize,
    pub flag_only: bool,
    pub sha256: String,
    /// False when it extends a hit already reported (same rule,
    /// overlapping): it still needs redacting, but is counted once.
    pub new: bool,
}

pub struct TextWindow {
    scanners: Vec<Arc<dyn Scanner>>,
    overlap: usize,
    cap: usize,
    buf: String,
    base: usize,
    /// Bytes of `buf` already scanned.
    scanned: usize,
    overflowed: bool,
    /// Spans already reported per (scanner, rule): disjoint intervals
    /// by start, so finding an overlap is a lookup, not a search.
    reported: HashMap<(String, String), BTreeMap<usize, usize>>,
}

impl TextWindow {
    pub fn new(scanners: Vec<Arc<dyn Scanner>>, cap: usize) -> Self {
        let longest = scanners
            .iter()
            .map(|s| s.max_match_len())
            .max()
            .unwrap_or(0);
        Self {
            scanners,
            overlap: longest.saturating_sub(1),
            cap,
            buf: String::new(),
            base: 0,
            scanned: 0,
            overflowed: false,
            reported: HashMap::new(),
        }
    }

    /// Absolute offset of the oldest text still held: nothing before it
    /// can be part of a future hit.
    pub fn base(&self) -> usize {
        self.base
    }

    pub fn end(&self) -> usize {
        self.base + self.buf.len()
    }

    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Bytes of text held.
    pub fn held(&self) -> usize {
        self.buf.len()
    }

    /// Append `text`; scan when enough is unscanned. Hits are reported
    /// once, by the scan that first sees them end in new text.
    pub fn push(&mut self, text: &str) -> Result<Vec<WindowHit>, ScanError> {
        self.buf.push_str(text);
        let unscanned = self.buf.len() - self.scanned;
        if unscanned == 0 || (unscanned * 8 < self.buf.len() && self.buf.len() <= self.cap) {
            return Ok(Vec::new());
        }
        self.scan()
    }

    /// Drop the held text once nothing will extend it (its output is
    /// finished and scanned). Offsets carry on from where they were.
    pub fn release_text(&mut self) {
        self.base += self.buf.len();
        self.buf = String::new();
        self.scanned = 0;
        self.reported = HashMap::new();
    }

    /// Scan whatever is still unscanned.
    pub fn flush(&mut self) -> Result<Vec<WindowHit>, ScanError> {
        if self.scanned == self.buf.len() {
            return Ok(Vec::new());
        }
        self.scan()
    }

    fn scan(&mut self) -> Result<Vec<WindowHit>, ScanError> {
        let old_end = self.scanned;
        self.scanned = self.buf.len();
        let mut out = Vec::new();
        for scanner in &self.scanners {
            for hit in scanner.scan(&self.buf, Direction::Response)? {
                if hit.end <= old_end {
                    continue;
                }
                let Some(matched) = self.buf.get(hit.start..hit.end) else {
                    return Err(ScanError(format!("{}: hit outside the text", scanner.id())));
                };
                let (start, end) = (self.base + hit.start, self.base + hit.end);
                let id = scanner.id().to_string();
                let spans = self
                    .reported
                    .entry((id.clone(), hit.rule.clone()))
                    .or_default();
                let new = !overlaps(spans, start, end);
                insert(spans, start, end);
                out.push(WindowHit {
                    scanner: id,
                    rule: hit.rule,
                    start,
                    end,
                    flag_only: hit.flag_only,
                    sha256: sha256_hex(matched),
                    new,
                });
            }
        }
        self.trim();
        Ok(out)
    }

    /// Drop text no future match can start in.
    fn trim(&mut self) {
        let keep = self.tail_start();
        let mut cut = keep.max(self.buf.len().saturating_sub(self.cap));
        while !self.buf.is_char_boundary(cut) {
            cut += 1;
        }
        if cut > keep {
            self.overflowed = true;
        }
        self.buf.drain(..cut);
        self.base += cut;
        self.scanned -= cut;
        let base = self.base;
        for spans in self.reported.values_mut() {
            while let Some((&a, &b)) = spans.first_key_value() {
                if b > base {
                    break;
                }
                spans.remove(&a);
            }
        }
        self.reported.retain(|_, spans| !spans.is_empty());
    }

    /// Start of the shortest tail at least `overlap` long, raw and folded.
    fn tail_start(&self) -> usize {
        let (mut raw, mut folded) = (0usize, 0usize);
        let mut later_space = false;
        for (at, c) in self.buf.char_indices().rev() {
            if raw >= self.overlap && folded >= self.overlap {
                return at + c.len_utf8();
            }
            raw += c.len_utf8();
            if c.is_whitespace() {
                if !later_space {
                    folded += 1;
                }
                later_space = true;
            } else if !normalize::is_invisible(c) {
                folded += normalize::folded_width(c);
                later_space = false;
            }
        }
        0
    }
}

/// Does `[start, end)` overlap any of the disjoint `spans`? Only the
/// last span starting before `end` can: the earlier ones end before it.
fn overlaps(spans: &BTreeMap<usize, usize>, start: usize, end: usize) -> bool {
    spans
        .range(..end)
        .next_back()
        .is_some_and(|(_, &b)| b > start)
}

/// Add `[start, end)` to `spans`, merging the spans it overlaps.
fn insert(spans: &mut BTreeMap<usize, usize>, mut start: usize, mut end: usize) {
    if start >= end {
        // An empty span covers nothing (and would replace one at `start`).
        return;
    }
    while let Some((&a, &b)) = spans.range(..end).next_back() {
        if b <= start {
            break;
        }
        spans.remove(&a);
        start = start.min(a);
        end = end.max(b);
    }
    spans.insert(start, end);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspection::injection::Injection;
    use crate::inspection::literal::Literal;

    fn literal(needle: &str, cap: usize) -> TextWindow {
        TextWindow::new(vec![Arc::new(Literal::new(needle).unwrap())], cap)
    }

    #[test]
    fn match_split_across_pushes_is_found_once() {
        let mut w = literal("SECRET42", 1 << 20);
        let mut hits = Vec::new();
        for c in "say SECRET42 twice".chars() {
            hits.extend(w.push(&c.to_string()).unwrap());
        }
        assert_eq!(hits.len(), 1);
        assert_eq!((hits[0].start, hits[0].end), (4, 12));
        assert!(hits[0].new);
    }

    #[test]
    fn a_hit_in_old_text_is_not_repeated() {
        let mut w = literal("SECRET42", 1 << 20);
        assert_eq!(w.push("xx SECRET42 yy").unwrap().len(), 1);
        assert!(w.push("zz").unwrap().is_empty());
        assert!(
            w.push(" SECRET42").unwrap().len() == 1,
            "a second occurrence counts"
        );
    }

    #[test]
    fn base_advances_but_keeps_the_overlap() {
        let mut w = literal("SECRET42", 1 << 20);
        for _ in 0..100 {
            w.push("abcd").unwrap();
        }
        assert_eq!(w.end(), 400);
        assert!(w.base() > 300, "base stuck at {}", w.base());
        assert!(w.end() - w.base() >= 7, "overlap lost");
    }

    #[test]
    fn folded_overlap_survives_whitespace_padding() {
        let mut w = TextWindow::new(vec![Arc::new(Injection)], 1 << 20);
        let mut hits = Vec::new();
        hits.extend(w.push("ignore all").unwrap());
        for _ in 0..300 {
            hits.extend(w.push(" ").unwrap());
        }
        hits.extend(w.push("previous instructions").unwrap());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].rule, "ignore_instructions");
        assert_eq!(hits[0].start, 0);
    }

    #[test]
    fn the_cap_bounds_what_is_held() {
        let mut w = TextWindow::new(vec![Arc::new(Injection)], 1000);
        for _ in 0..2000 {
            w.push("\u{200B}").unwrap();
        }
        assert!(w.end() - w.base() <= 1000);
        assert!(w.overflowed());
    }

    /// Counts the bytes it is asked to scan.
    struct Counting(std::sync::atomic::AtomicUsize);

    impl Scanner for Counting {
        fn id(&self) -> &str {
            "counting"
        }
        fn max_match_len(&self) -> usize {
            64
        }
        fn scan(&self, text: &str, _: Direction) -> Result<Vec<super::super::Hit>, ScanError> {
            self.0
                .fetch_add(text.len(), std::sync::atomic::Ordering::Relaxed);
            Ok(Vec::new())
        }
    }

    #[test]
    fn padding_does_not_make_scanning_quadratic() {
        let counting = Arc::new(Counting(Default::default()));
        let mut w = TextWindow::new(vec![counting.clone()], 1 << 20);
        let pushed = 50_000;
        for _ in 0..pushed {
            w.push(" ").unwrap();
        }
        w.flush().unwrap();
        let scanned = counting.0.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            scanned <= 20 * pushed,
            "scanned {scanned} bytes for {pushed}"
        );
    }

    #[test]
    fn flush_reports_a_match_still_unscanned() {
        let mut w = literal("SECRET42", 1 << 20);
        let mut hits = Vec::new();
        for _ in 0..200 {
            hits.extend(w.push("abcdefgh ").unwrap());
        }
        hits.extend(w.push("SECRET42").unwrap());
        hits.extend(w.flush().unwrap());
        assert_eq!(hits.len(), 1, "{hits:?}");
    }
}
