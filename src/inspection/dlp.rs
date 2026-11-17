//! AGENT-263 — `dlp`: credential and secret patterns.
//!
//! Locksmith's own curated rules (not a port of another tool's set). Every
//! rule has a fixed upper bound on what it can match, which streaming
//! scanning uses as its window overlap. Base64 runs of 24..=4096 characters
//! are decoded once (at each of the four alignments, so text glued to the
//! run's start doesn't hide it) and the decoded text scanned with the same
//! rules, so an encoded key is still found. A Shannon-entropy heuristic catches unknown
//! formats; it is noisy, so its hits only ever flag.

use super::{Direction, Hit, ScanError, Scanner};
use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use regex::Regex;
use std::sync::LazyLock;

/// Entropy heuristic: bits per character over a run of this many characters.
const ENTROPY_BITS: f64 = 4.5;
const ENTROPY_RUN: (usize, usize) = (32, 128);
/// `Bearer` is strong context; this only rejects repetitive filler.
const BEARER_BITS: f64 = 3.0;
/// Base64 runs decoded (one level), in characters before padding.
const BASE64_RUN: (usize, usize) = (24, 4096);

const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

struct Rule {
    id: &'static str,
    re: Regex,
    /// Longest match the pattern allows.
    max_len: usize,
    /// Extra test on the reported span.
    check: Option<fn(&str) -> bool>,
    /// Grows a match past what the pattern matched.
    extend: Option<Extend>,
}

/// Grows a match past its regex: `(text, match end, END lines)`.
type Extend = fn(&str, usize, &[(usize, usize)]) -> usize;

fn rule(id: &'static str, pattern: &str, max_len: usize, check: Option<fn(&str) -> bool>) -> Rule {
    Rule {
        id,
        re: Regex::new(pattern).expect("dlp rule compiles"),
        max_len,
        check,
        extend: None,
    }
}

/// Longest PEM body an END line is looked for across. Past it, or with
/// no END, the key is followed line by line to its end.
const PEM_BODY_MAX: usize = 8192;
const PEM_HEADER_MAX: usize = 47;

const PEM_BEGIN_PATTERN: &str = r"(?-u)-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----";
static PEM_BEGIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(PEM_BEGIN_PATTERN).expect("compiles"));
static PEM_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)-----END [A-Z ]{0,20}PRIVATE KEY-----").expect("compiles"));

fn is_base64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"+/=".contains(&b)
}

/// One character of a PEM window as a JSON reader would see it: a raw
/// byte, or an escape decoded. `byte` is 0xFF for anything outside ASCII;
/// `end` is where the character ends in the window.
struct Unit {
    byte: u8,
    end: usize,
    /// Written as an escape. After a key's last line any escape ends it,
    /// as a raw backslash would.
    escaped: bool,
}

/// Decode `window` into characters (AGENT-270), lazily: the caller
/// usually stops at the key's first non-key line. Inside a JSON string,
/// nested to any depth, a key's line breaks, indentation and even its
/// base64 may be escapes: a run of backslashes and what it escapes is one
/// character. A run that escapes nothing a key uses stays a backslash.
struct PemUnits<'a> {
    b: &'a [u8],
    i: usize,
}

impl Iterator for PemUnits<'_> {
    type Item = Unit;

    fn next(&mut self) -> Option<Unit> {
        let (b, i) = (self.b, self.i);
        let first = *b.get(i)?;
        if first != b'\\' {
            self.i += 1;
            let byte = if first.is_ascii() { first } else { 0xFF };
            return Some(Unit {
                byte,
                end: self.i,
                escaped: false,
            });
        }
        let run = b[i..].iter().take_while(|&&c| c == b'\\').count();
        let rest = &b[i + run..];
        let (byte, len) = match rest.first() {
            Some(b'n') => (b'\n', 1),
            Some(b't') => (b'\t', 1),
            Some(b'r') => (b'\r', 1),
            Some(&c @ (b'/' | b'"')) => (c, 1),
            Some(b'u') if rest.len() >= 5 && rest[1..5].iter().all(u8::is_ascii_hexdigit) => {
                let hex = std::str::from_utf8(&rest[1..5]).expect("hex digits");
                let code = u32::from_str_radix(hex, 16).expect("hex digits");
                let byte = u8::try_from(code).ok().filter(u8::is_ascii);
                (byte.unwrap_or(0xFF), 5)
            }
            _ => (b'\\', 0),
        };
        self.i += run + len;
        Some(Unit {
            byte,
            end: self.i,
            escaped: true,
        })
    }
}

/// A line without its indentation and trailing spaces (a key pasted into
/// YAML or code).
fn trimmed(line: &[Unit]) -> &[Unit] {
    let blank = |u: &Unit| matches!(u.byte, b' ' | b'\t' | b'\r');
    let start = line.iter().position(|u| !blank(u)).unwrap_or(line.len());
    let end = line
        .iter()
        .rposition(|u| !blank(u))
        .map_or(start, |p| p + 1);
    &line[start..end]
}

fn starts_with(line: &[Unit], prefix: &[u8]) -> bool {
    line.len() >= prefix.len() && line.iter().zip(prefix).all(|(u, b)| u.byte == *b)
}

/// What may follow a key's last line on the same line: whitespace, a
/// control byte, a closing quote or bracket, punctuation, or any non-ASCII
/// character (a raw `”` from a UTF-8 encoder). Not `:`, so a YAML key on
/// the next line is not taken for base64.
fn closes(b: u8) -> bool {
    !(0x20..0x80).contains(&b) || b" \"'}],\\<>);`.!?&|".contains(&b)
}

/// Did `pem_extend` stop the key starting at `start` at the END line
/// `text[..end]` ends with? Only one within `PEM_BODY_MAX` of the BEGIN
/// line counts: past it the key is walked, and a walked header line may
/// end in END text with the key lines still to come (AGENT-311).
fn closed_by_end_line(text: &str, start: usize, end: usize) -> bool {
    let begin = PEM_BEGIN
        .find_at(text, start)
        .filter(|m| m.start() == start);
    begin.is_some_and(|b| end >= b.end() && end - b.end() <= PEM_BODY_MAX)
        && ends_at_end_line(text, end)
}

/// Does `text[..end]` end with an END line? (A BEGIN line ends with
/// `PRIVATE KEY-----` too.)
fn ends_at_end_line(text: &str, end: usize) -> bool {
    let mut from = end.saturating_sub(PEM_HEADER_MAX);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    PEM_END
        .find_iter(&text[from..end])
        .any(|m| from + m.end() == end)
}

/// Could the key a `private_key` hit ending at `end` still go on? Only
/// blanks, the line breaks before its next line (two, after RFC 1421
/// headers) and an escape the text's end split may follow it.
fn pem_open(text: &str, end: usize) -> bool {
    let mut units = PemUnits {
        b: &text.as_bytes()[end..],
        i: 0,
    };
    let (mut breaks, mut tail) = (0, Vec::new());
    for u in &mut units {
        match u.byte {
            b' ' | b'\t' | b'\r' if tail.is_empty() => {}
            b'\n' if tail.is_empty() && breaks < 2 => breaks += 1,
            _ if tail.len() < 5 => tail.push(u),
            _ => return false,
        }
    }
    // A split escape: a lone backslash, then what was cut of a `\uXXXX`.
    let hex = |u: &Unit| !u.escaped && u.byte.is_ascii_hexdigit();
    match tail.split_first() {
        None => true,
        Some((first, rest)) => {
            first.escaped
                && first.byte == b'\\'
                && rest.first().is_none_or(|u| !u.escaped && u.byte == b'u')
                && rest.iter().skip(1).all(hex)
        }
    }
}

/// Read one line of a PEM body into `line`; false at the end of the text.
/// A line that cannot be key or header stops a few characters past its
/// first such character (enough to see a split escape), so packed BEGIN
/// lines cost linear time; true then, as more of it follows.
fn read_line(units: &mut PemUnits, line: &mut Vec<Unit>, may_be_header: bool) -> bool {
    let mut odd = None;
    let mut header = false;
    loop {
        match units.next() {
            Some(u) if u.byte == b'\n' => return true,
            Some(u) => {
                let blank = matches!(u.byte, b' ' | b'\t' | b'\r');
                if odd.is_none() && !blank && !is_base64(u.byte) {
                    odd = Some(line.len());
                }
                line.push(u);
            }
            None => return false,
        }
        if !header && odd.is_some_and(|o| line.len() == o + 9) {
            // Decided once: a header line is read whole.
            header = may_be_header && is_header(trimmed(line));
            if !header {
                return true;
            }
        }
    }
}

/// How reading the rest of a BEGIN line stopped.
#[derive(PartialEq)]
enum JoinedStop {
    /// A line break: the key may go on, line by line.
    Newline,
    /// The end of the text.
    End,
    /// A `-----` marker (an END or another BEGIN line), or a character
    /// a key or its headers cannot hold.
    Other,
}

/// Read the rest of a BEGIN line into `line`. A key may be joined onto it
/// with spaces, headers and all (`-----BEGIN RSA PRIVATE KEY----- Proc-Type:
/// 4,ENCRYPTED DEK-Info: ... MIIE...`), so base64, blanks and the header
/// characters `:`, `,` and `-` are read (AGENT-311). It stops at the next
/// `-----`, so BEGIN lines packed onto one line cost linear time.
fn read_joined(units: &mut PemUnits, line: &mut Vec<Unit>) -> JoinedStop {
    loop {
        let Some(u) = units.next() else {
            return JoinedStop::End;
        };
        match u.byte {
            b'\n' => return JoinedStop::Newline,
            b' ' | b'\t' | b'\r' | b':' | b',' | b'-' => {}
            b if is_base64(b) => {}
            _ => return JoinedStop::Other,
        }
        line.push(u);
        let dashes = line.iter().rev().take_while(|u| u.byte == b'-').count();
        if dashes == 5 {
            line.truncate(line.len() - 5);
            return JoinedStop::Other;
        }
    }
}

/// Where a key on its BEGIN line ends, and whether all of the line was
/// key or headers. One base64 word is a key line however short (the key's
/// first line on the BEGIN line). Several words are a key joined onto it
/// with spaces when one is base64 of at least `JOINED_WORD_MIN`
/// characters; the others may be RFC 1421 header words (holding `:` or
/// `,`) or shorter base64. At `at_end`, the text stops inside the line, so
/// headers then a word not yet long count too. Prose (`-----BEGIN PRIVATE
/// KEY----- and so on`) has no long word, so it is not taken for a key.
fn joined_key(body: &[Unit], at_end: bool) -> (Option<usize>, bool) {
    let mut end = None;
    let (mut long, mut base64_words, mut headers, mut words) = (false, 0, 0, 0);
    let mut last_base64 = false;
    let mut whole = true;
    for word in body
        .split(|u| matches!(u.byte, b' ' | b'\t' | b'\r'))
        .filter(|w| !w.is_empty())
    {
        words += 1;
        last_base64 = word.iter().all(|u| is_base64(u.byte));
        if last_base64 {
            base64_words += 1;
            long |= word.len() >= JOINED_WORD_MIN;
            end = word.last().map(|u| u.end);
        } else if word.iter().any(|u| matches!(u.byte, b':' | b',')) {
            headers += 1;
        } else {
            whole = false;
            break;
        }
    }
    let cut_short = at_end && whole && headers > 0 && last_base64;
    if long || (words == 1 && base64_words == 1) || cut_short {
        (end, whole)
    } else {
        (None, whole && base64_words == 0)
    }
}

/// The shortest base64 word taken for key material on a BEGIN line.
const JOINED_WORD_MIN: usize = 16;

fn is_header(body: &[Unit]) -> bool {
    starts_with(body, b"Proc-Type:") || starts_with(body, b"DEK-Info:")
}

/// The whole PEM block after a BEGIN line: through an END line within
/// `PEM_BODY_MAX`, or else through the base64 and RFC 1421 header lines
/// that follow, however long (AGENT-309). Redacting only the BEGIN line
/// would leave the key. Where a stream's text stops inside the key, the
/// hit ends at or just before that point, so the window holds it open.
fn pem_extend(text: &str, header_end: usize, ends: &[(usize, usize)]) -> usize {
    let next = ends.partition_point(|&(start, _)| start < header_end);
    if let Some(&(_, end)) = ends
        .get(next)
        .filter(|(_, e)| e - header_end <= PEM_BODY_MAX)
    {
        return end;
    }
    let mut units = PemUnits {
        b: &text.as_bytes()[header_end..],
        i: 0,
    };
    let mut end = 0;
    let mut after_header = false;
    let mut seen_key = false;
    let mut line = Vec::new();
    // The rest of the BEGIN line: empty, or a key joined onto it.
    let stop = read_joined(&mut units, &mut line);
    let at_end = stop == JoinedStop::End
        && line
            .last()
            .is_some_and(|u| !matches!(u.byte, b' ' | b'\t' | b'\r'));
    let joined = trimmed(&line);
    let (joined_end, whole) = joined_key(joined, at_end);
    if let Some(e) = joined_end {
        end = e;
        seen_key = true;
    } else if whole && !joined.is_empty() {
        // Header words only: the RFC 1421 blank line may follow.
        end = joined.last().map_or(end, |u| u.end);
        after_header = true;
    }
    if !whole || stop != JoinedStop::Newline {
        return header_end + end;
    }
    for i in 1.. {
        line.clear();
        // RFC 1421 headers (`Proc-Type`, `DEK-Info`) are the two lines
        // after BEGIN: more would let packed headers walk the whole text.
        let may_be_header = (1..=2).contains(&i) && !seen_key;
        let more = read_line(&mut units, &mut line, may_be_header);
        let body = trimmed(&line);
        let key = body.iter().take_while(|u| is_base64(u.byte)).count();
        let header = may_be_header && is_header(body);
        if (key > 0 && key == body.len()) || header {
            end = body.last().map_or(end, |u| u.end);
            after_header = header;
            seen_key |= !header;
        } else if !(body.is_empty() && after_header) {
            // Anything but a blank line after RFC 1421 headers ends the
            // block. Blank lines after
            // headers are not limited to one: covering more of a body is
            // the safe side, and a stream keeps the BEGIN line held
            // across them as whitespace (AGENT-311). A key quoted in a
            // string ends its last line with the closing quote
            // (`AB==\"}`), and prose may follow on the same line: that
            // base64 is the key too.
            if key > 0 && body.get(key).is_some_and(|u| u.escaped || closes(u.byte)) {
                end = body[key - 1].end;
            }
            break;
        }
        if !more {
            break;
        }
    }
    header_end + end
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        rule(
            "aws_access_key_id",
            r"(?-u)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            20,
            None,
        ),
        rule(
            "github_token",
            r"(?-u)\b(?:(?:ghp|gho|ghs)_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{22,255})\b",
            266,
            None,
        ),
        rule(
            "slack_token",
            r"(?-u)\bxox[abprs]-[A-Za-z0-9-]{10,250}",
            255,
            None,
        ),
        rule(
            "anthropic_key",
            r"(?-u)\bsk-ant-[A-Za-z0-9_-]{20,300}",
            307,
            None,
        ),
        rule(
            "openai_key",
            r"(?-u)\bsk-(?:proj-)?[A-Za-z0-9_-]{20,300}",
            308,
            Some(|m| !m.starts_with("sk-ant-") && mixed(&m[3..])),
        ),
        rule("google_api_key", r"(?-u)\bAIza[0-9A-Za-z_-]{35}", 39, None),
        rule(
            "stripe_live_key",
            r"(?-u)\bsk_live_[0-9A-Za-z]{24,99}",
            107,
            None,
        ),
        Rule {
            extend: Some(pem_extend),
            ..rule(
                "private_key",
                PEM_BEGIN_PATTERN,
                PEM_HEADER_MAX + PEM_BODY_MAX,
                None,
            )
        },
        rule(
            "jwt",
            // A payload past 4096 characters (AGENT-270) is matched as
            // its header and first 4097 payload characters: enough to
            // remove the token without widening the stream window.
            r"(?-u)\beyJ[A-Za-z0-9_-]{5,2048}\.(?:[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{5,1024}|[A-Za-z0-9_-]{4097})",
            7173,
            Some(jwt_header_has_alg),
        ),
        // Group 1 is the token: the span reported (and redacted) is the
        // credential, not the scheme word.
        rule(
            "bearer",
            r"(?-u)\bBearer[ \t]{1,4}([A-Za-z0-9._~+/=-]{40,1024})",
            1024,
            Some(|t| entropy(t) >= BEARER_BITS),
        ),
    ]
});

static ENTROPY_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)[A-Za-z0-9+/=_-]{32,}").expect("compiles"));
static BASE64_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)[A-Za-z0-9+/]{24,}={0,2}").expect("compiles"));

/// Digits and both letter cases: separates generated keys from words.
fn mixed(s: &str) -> bool {
    s.bytes().any(|b| b.is_ascii_digit())
        && s.bytes().any(|b| b.is_ascii_uppercase())
        && s.bytes().any(|b| b.is_ascii_lowercase())
}

/// Shannon entropy in bits per byte.
fn entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn jwt_header_has_alg(m: &str) -> bool {
    let header = m.split('.').next().unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .is_some_and(|v| v.get("alg").is_some())
}

/// Every named-rule match in `text`, as (rule, start, end).
fn rule_hits(text: &str) -> Vec<(&'static str, usize, usize)> {
    let mut out = Vec::new();
    // END lines, found once: looking for one after each BEGIN would cost
    // the window per BEGIN.
    let pem_ends = std::cell::OnceCell::<Vec<(usize, usize)>>::new();
    for r in RULES.iter() {
        for caps in r.re.captures_iter(text) {
            let m = caps.get(1).or_else(|| caps.get(0)).expect("group 0");
            if m.len() <= r.max_len && r.check.is_none_or(|c| c(m.as_str())) {
                let end = r.extend.map_or(m.end(), |grow| {
                    let ends = pem_ends.get_or_init(|| {
                        PEM_END
                            .find_iter(text)
                            .map(|e| (e.start(), e.end()))
                            .collect()
                    });
                    grow(text, m.end(), ends)
                });
                out.push((r.id, m.start(), end));
            }
        }
    }
    out
}

/// Base64 runs whose one-level decode holds a named-rule match.
fn base64_hits(text: &str) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    for m in BASE64_CANDIDATE.find_iter(text) {
        let body = m.as_str().trim_end_matches('=');
        if body.len() < BASE64_RUN.0 || body.len() > BASE64_RUN.1 {
            continue;
        }
        // AGENT-270: text glued to the run's start (`token<base64>`)
        // shifts every quantum, so try each alignment. What the prefix
        // decodes to is garbage, so decode lossily.
        let found = (0..4).find_map(|skip| {
            let decoded = LENIENT_BASE64.decode(body.get(skip..)?).ok()?;
            let decoded = String::from_utf8_lossy(&decoded);
            rule_hits(&decoded).first().map(|(id, ..)| *id)
        });
        if let Some(id) = found {
            out.push((format!("base64:{id}"), m.start(), m.end()));
        }
    }
    out
}

fn overlaps(hits: &[Hit], start: usize, end: usize) -> bool {
    hits.iter().any(|h| h.start < end && start < h.end)
}

pub(crate) struct Dlp;

impl Scanner for Dlp {
    fn id(&self) -> &str {
        "dlp"
    }

    fn holds_open(&self, text: &str, hit: &Hit) -> bool {
        // A key its END line closed is over (AGENT-311): many BEGIN lines
        // share one END, and walking the text after it once per hit would
        // cost each scan their number times the padding.
        hit.rule == "private_key"
            && !closed_by_end_line(text, hit.start, hit.end)
            && pem_open(text, hit.end)
    }

    fn max_match_len(&self) -> usize {
        let rules = RULES.iter().map(|r| r.max_len).max().unwrap_or(0);
        rules.max(ENTROPY_RUN.1).max(BASE64_RUN.1 + 2)
    }

    fn scan(&self, text: &str, _: Direction) -> Result<Vec<Hit>, ScanError> {
        let hit = |rule: String, start, end, flag_only| Hit {
            rule,
            start,
            end,
            flag_only,
        };
        let mut hits: Vec<Hit> = rule_hits(text)
            .into_iter()
            .map(|(id, s, e)| hit(id.to_string(), s, e, false))
            .collect();
        hits.extend(
            base64_hits(text)
                .into_iter()
                .map(|(id, s, e)| hit(id, s, e, false)),
        );
        // The heuristic only reports what no named rule already covers.
        let entropic: Vec<Hit> = ENTROPY_CANDIDATE
            .find_iter(text)
            .filter(|m| (ENTROPY_RUN.0..=ENTROPY_RUN.1).contains(&m.len()))
            .filter(|m| entropy(m.as_str()) >= ENTROPY_BITS)
            .filter(|m| !overlaps(&hits, m.start(), m.end()))
            .map(|m| hit("entropy".into(), m.start(), m.end(), true))
            .collect();
        hits.extend(entropic);
        hits.sort_by_key(|h| (h.start, h.end));
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BodyMeta, DirectionPolicy, OnError, Outcome, Verdict, apply, apply_with};
    use super::*;
    use base64::Engine;
    use std::sync::Arc;

    /// Deterministic generator, so a failing line reproduces.
    struct Gen(u64);
    impl Gen {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn chars(&mut self, alphabet: &[u8], n: usize) -> String {
            (0..n)
                .map(|_| alphabet[(self.next() % alphabet.len() as u64) as usize] as char)
                .collect()
        }
    }

    const UP: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const AN: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const ANU: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    const DIG: &[u8] = b"0123456789";

    fn b64url(s: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
    }

    /// Expand a fixture template's placeholders with generated characters.
    fn expand(template: &str, g: &mut Gen) -> String {
        let mut out = String::new();
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let close = open + rest[open..].find('}').expect("unclosed placeholder");
            let token = &rest[open + 1..close];
            let (kind, n) = token.split_once(':').unwrap_or((token, "0"));
            let n: usize = n.parse().unwrap();
            out.push_str(&match kind {
                "UP" => g.chars(UP, n),
                "AN" => g.chars(AN, n),
                "ANU" => g.chars(ANU, n),
                "DIG" => g.chars(DIG, n),
                "D5" => "-----".into(),
                "JWT" => format!(
                    "{}.{}.{}",
                    b64url(r#"{"alg":"HS256","typ":"JWT"}"#),
                    b64url(&format!(
                        r#"{{"sub":"{}","iat":1700000000}}"#,
                        g.chars(AN, 12)
                    )),
                    g.chars(ANU, 43)
                ),
                other => panic!("unknown placeholder {other}"),
            });
            rest = &rest[close + 1..];
        }
        out.push_str(rest);
        out
    }

    fn lines(fixture: &str) -> impl Iterator<Item = &str> {
        fixture
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
    }

    fn scan(text: &str) -> Vec<Hit> {
        Dlp.scan(text, Direction::Request).unwrap()
    }

    #[test]
    fn each_rule_matches_its_true_positive() {
        let fixture = include_str!("../../tests/fixtures/inspection/dlp_true.txt");
        let mut g = Gen(0x9e37_79b9_7f4a_7c15);
        for line in lines(fixture) {
            let (rule, template) = line.split_once('\t').expect("rule<TAB>line");
            let text = expand(template, &mut g);
            let start = text.find("[[").unwrap();
            let end = text.find("]]").unwrap() - 2;
            let text = text.replace("[[", "").replace("]]", "");
            let hits = scan(&text);
            let found: Vec<_> = hits
                .iter()
                .map(|h| (h.rule.as_str(), h.start, h.end))
                .collect();
            assert_eq!(found, vec![(rule, start, end)], "line: {template}");
            assert!(end - start <= Dlp.max_match_len(), "{rule} exceeds bound");
            assert_eq!(hits[0].flag_only, rule == "entropy", "{rule} flag_only");
        }
    }

    #[test]
    fn false_positive_corpus_is_clean() {
        let fixture = include_str!("../../tests/fixtures/inspection/dlp_false.txt");
        for line in lines(fixture) {
            let hits = scan(line);
            assert!(hits.is_empty(), "false positive {hits:?} in: {line:.80}");
        }
    }

    fn block_policy() -> DirectionPolicy {
        DirectionPolicy {
            scanners: vec![Arc::new(Dlp)],
            on_hit: Verdict::Block,
            on_error: OnError::FailClosed,
            max_scan_bytes: 1 << 20,
        }
    }

    fn json_rules(body: &str) -> Vec<String> {
        let meta = BodyMeta {
            content_type: Some("application/json"),
            encoded: false,
        };
        match apply(&block_policy(), Direction::Request, meta, body.as_bytes()) {
            Outcome::Block { report } => report.hits.into_iter().map(|h| h.rule).collect(),
            Outcome::Forward { .. } => Vec::new(),
        }
    }

    #[test]
    fn key_inside_escaped_json_string_is_found() {
        let mut g = Gen(7);
        // `g` is `g`: the token only exists after JSON unescaping.
        let body = format!(
            r#"{{"msg":"line one\ntoken=\u0067hp_{}\t(end)"}}"#,
            g.chars(AN, 36)
        );
        assert_eq!(json_rules(&body), vec!["github_token"]);
    }

    #[test]
    fn base64_encoded_key_in_json_field_is_found() {
        let mut g = Gen(11);
        let plain = format!("aws_access_key_id = AKIA{}", g.chars(UP, 16));
        let encoded = base64::engine::general_purpose::STANDARD.encode(plain);
        let body = format!(r#"{{"attachment":"{encoded}"}}"#);
        assert_eq!(json_rules(&body), vec!["base64:aws_access_key_id"]);
    }

    #[test]
    fn base64_run_beyond_the_decode_bound_is_not_decoded() {
        let mut g = Gen(13);
        let plain = format!("AKIA{} {}", g.chars(UP, 16), "x".repeat(3200));
        let encoded = base64::engine::general_purpose::STANDARD.encode(plain);
        assert!(encoded.len() > 4096);
        assert!(scan(&encoded).is_empty());
    }

    #[test]
    fn a_base64_run_glued_to_preceding_text_is_still_decoded() {
        // AGENT-270: letters before the run join it, shifting every
        // quantum; the decode has to realign.
        let mut g = Gen(19);
        let plain = format!("aws_access_key_id = AKIA{}", g.chars(UP, 16));
        let encoded = base64::engine::general_purpose::STANDARD.encode(plain);
        for prefix in ["t", "to", "tok", "toke", "token"] {
            let body = format!(r#"{{"note":"{prefix}{encoded}"}}"#);
            assert_eq!(
                json_rules(&body),
                vec!["base64:aws_access_key_id"],
                "{prefix}"
            );
        }
    }

    #[test]
    fn a_jwt_with_an_oversized_payload_is_still_found() {
        let mut g = Gen(23);
        let header = b64url(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = g.chars(ANU, 6000);
        let jwt = format!("{header}.{payload}.{}", g.chars(ANU, 342));
        let hits = scan(&format!("token: {jwt} end"));
        let jwt_hit = hits.iter().find(|h| h.rule == "jwt").expect("jwt found");
        // The span starts at the token and covers its header and
        // the payload's first 4097 characters.
        assert_eq!(jwt_hit.start, 7);
        assert_eq!(jwt_hit.end - jwt_hit.start, header.len() + 1 + 4097);
        assert!(Dlp.max_match_len() >= jwt_hit.end - jwt_hit.start);
    }

    #[test]
    fn whole_pem_block_is_one_hit() {
        let mut g = Gen(17);
        let body: Vec<String> = (0..6).map(|_| g.chars(AN, 64)).collect();
        for (kind, headers) in [
            ("RSA ", ""),
            (
                "RSA ",
                "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCDEF0123456789\n\n",
            ),
            ("", ""),
        ] {
            let block = format!(
                "-----BEGIN {kind}PRIVATE KEY-----\n{headers}{}\n-----END {kind}PRIVATE KEY-----",
                body.join("\n")
            );
            let text = format!("key:\n{block}\nand more prose");
            let h: Vec<_> = scan(&text)
                .into_iter()
                .filter(|h| h.rule == "private_key")
                .collect();
            assert_eq!(h.len(), 1, "{kind}{headers}");
            assert_eq!(&text[h[0].start..h[0].end], block);
            assert!(
                scan(&text).iter().all(|x| x.rule == "private_key"),
                "extra hits"
            );
        }
    }

    #[test]
    fn pem_without_end_covers_the_body_lines() {
        let mut g = Gen(19);
        let body = format!("{}\n{}", g.chars(AN, 64), g.chars(AN, 40));
        let text = format!("-----BEGIN PRIVATE KEY-----\n{body}\n\nAfter the cut.");
        let h = &scan(&text)[0];
        assert_eq!(h.rule, "private_key");
        assert_eq!(
            &text[h.start..h.end],
            format!("-----BEGIN PRIVATE KEY-----\n{body}")
        );
    }

    #[test]
    fn pem_without_end_covers_escaped_body_lines() {
        // AGENT-270: inside a JSON string the line breaks are `\n` (or
        // `\\n` one level deeper); the whole body is still the key.
        let mut g = Gen(41);
        let lines = [g.chars(AN, 64), g.chars(AN, 40)];
        for nl in ["\\n", "\\\\n", "\\r\\n"] {
            let block = format!(
                "-----BEGIN PRIVATE KEY-----{nl}{}{nl}{}",
                lines[0], lines[1]
            );
            let text = format!("{block}{nl}{nl}After the cut.");
            let h = &scan(&text)[0];
            assert_eq!(h.rule, "private_key");
            assert_eq!(&text[h.start..h.end], block, "{nl}");
        }
    }

    #[test]
    fn indented_pem_with_trailing_spaces_and_no_end_is_one_hit() {
        // AGENT-270: a key pasted into YAML or code is indented, and
        // editors leave trailing spaces.
        let mut g = Gen(47);
        let lines = [g.chars(AN, 64), g.chars(AN, 64), g.chars(AN, 12)];
        let block = format!(
            "-----BEGIN PRIVATE KEY-----\n    {}  \n    {}\t\n    {}",
            lines[0], lines[1], lines[2]
        );
        let text = format!("key: |\n  {block}\nnext: value");
        let h = &scan(&text)[0];
        assert_eq!(h.rule, "private_key");
        assert_eq!(&text[h.start..h.end], block);
    }

    #[test]
    fn a_pem_key_without_end_in_nested_tool_arguments_is_removed() {
        // Review finding: only the BEGIN line was redacted and the body
        // was forwarded.
        let mut g = Gen(43);
        let lines: Vec<String> = (0..3).map(|_| g.chars(AN, 64)).collect();
        let pem = format!("-----BEGIN RSA PRIVATE KEY-----\n{}", lines.join("\n"));
        let inner = serde_json::json!({ "key": pem }).to_string();
        let body = serde_json::json!({ "args": inner }).to_string();
        match outcome("application/json", body.as_bytes(), Verdict::Redact) {
            Outcome::Forward { body: Some(b), .. } => {
                let b = String::from_utf8(b).unwrap();
                assert!(lines.iter().all(|l| !b.contains(l.as_str())), "{b}");
            }
            Outcome::Forward { body: None, .. } => panic!("forwarded unredacted"),
            Outcome::Block { .. } => {}
        }
    }

    /// A nested-arguments body holding `pem` with each inner `from` byte
    /// written as `to` (how some JSON encoders escape `/` and `+`).
    fn nested_args(pem: &str, from: char, to: &str) -> String {
        let inner = serde_json::json!({ "key": pem })
            .to_string()
            .replace(from, to);
        serde_json::json!({ "args": inner }).to_string()
    }

    fn assert_redacted_whole(body: &str, parts: &[String]) {
        match outcome("application/json", body.as_bytes(), Verdict::Redact) {
            Outcome::Forward {
                body: Some(b),
                report,
            } => {
                let b = String::from_utf8(b).unwrap();
                assert!(parts.iter().all(|p| !b.contains(p.as_str())), "{b}");
                assert!(!report.redaction_incomplete);
            }
            Outcome::Forward { body: None, .. } => panic!("forwarded unredacted"),
            Outcome::Block { .. } => panic!("blocked instead of redacted"),
        }
    }

    #[test]
    fn escaped_slash_and_plus_in_nested_pem_lines_do_not_cut_the_key() {
        // Review finding: `\/` (PHP, json-c) or `\u002B` (.NET) inside a
        // line ended the match there and forwarded the rest of the key.
        let mut g = Gen(53);
        let parts: Vec<String> = (0..6).map(|_| g.chars(AN, 20)).collect();
        let pem = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}/{}+{}\n{}+{}/{}",
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        );
        assert_redacted_whole(&nested_args(&pem, '/', "\\/"), &parts);
        assert_redacted_whole(&nested_args(&pem, '+', "\\u002B"), &parts);
    }

    #[test]
    fn any_hex_escape_of_a_base64_byte_or_newline_keeps_the_key_whole() {
        // Review finding: an encoder (or an adversary) can write any
        // character as `\u00XX`, including the line break.
        let mut g = Gen(67);
        let parts: Vec<String> = (0..6).map(|_| g.chars(AN, 20)).collect();
        let pem = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}={}={}\n{}={}\n{}",
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        );
        let body = nested_args(&pem, '=', "\\u003D");
        let body = body.replace("\\\\n", "\\\\u000A");
        assert!(body.contains("u003D") && body.contains("u000A"), "{body}");
        assert_redacted_whole(&body, &parts);
    }

    #[test]
    fn escaped_whitespace_and_any_hex_case_in_nested_pem_keep_the_key_whole() {
        // Review finding: tab indentation is `\t` inside a string, which
        // ended the block. Escapes are decoded as a JSON reader would.
        let mut g = Gen(71);
        let parts: Vec<String> = (0..6).map(|_| g.chars(AN, 20)).collect();
        let lines = format!(
            "\n\t{}={}\n\t{}={}\r\n\t{}={}",
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        );
        let pem = format!("-----BEGIN RSA PRIVATE KEY-----{lines}");
        assert_redacted_whole(&nested_args(&pem, '~', "~"), &parts);
        // Lowercase hex, a `\u0009` tab, and CR LF as `\u` escapes.
        let body = nested_args(&pem, '=', "\\u003d")
            .replace("\\\\t", "\\\\u0009")
            .replace("\\\\r\\\\n", "\\\\u000D\\\\u000a");
        assert!(body.contains("u0009") && body.contains("u000a"), "{body}");
        assert_redacted_whole(&body, &parts);
    }

    #[test]
    fn a_last_nested_key_line_before_an_escaped_tab_or_full_stop_is_kept() {
        // Codex review: decoding `\t` dropped the last line that a bare
        // `\` terminator used to keep.
        let mut g = Gen(73);
        let parts: Vec<String> = (0..2).map(|_| g.chars(AN, 40)).collect();
        for tail in ["\t(note)", ". Thanks", "\r\t", "&more"] {
            let pem = format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{}\n{}{tail}",
                parts[0], parts[1]
            );
            assert_redacted_whole(&nested_args(&pem, '~', "~"), &parts);
        }
        // Round 2 review: an ASCII-only encoder (Python's default) writes
        // a closing curly quote as `\u201d`; any escape ends the line.
        let pem = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n{}\u{201d}",
            parts[0], parts[1]
        );
        let body = nested_args(&pem, '\u{201d}', "\\u201d");
        assert!(body.contains("u201d"), "{body}");
        assert_redacted_whole(&body, &parts);
    }

    #[test]
    fn a_last_key_line_before_a_raw_non_ascii_or_control_character_is_kept() {
        // Round 3 review: a UTF-8 encoder writes `”` raw, and `\b` is a
        // raw control byte one level up; either ends the line.
        let mut g = Gen(79);
        let parts: Vec<String> = (0..2).map(|_| g.chars(AN, 40)).collect();
        for tail in ["\u{201d} he said", "\u{8}", "\u{e9}t\u{e9}"] {
            let pem = format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{}\n{}{tail}",
                parts[0], parts[1]
            );
            assert_redacted_whole(&nested_args(&pem, '~', "~"), &parts);
            let h = &scan(&pem)[0];
            assert!(pem[h.end..].starts_with(tail), "{tail:?}");
        }
    }

    #[test]
    fn an_indented_blank_line_after_rfc1421_headers_keeps_the_key() {
        let mut g = Gen(59);
        let line = g.chars(AN, 64);
        let block = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n    Proc-Type: 4,ENCRYPTED\n    DEK-Info: AES-128-CBC,ABCDEF0123456789\n    \n    {line}"
        );
        let text = format!("{block}\n\nprose");
        let h = &scan(&text)[0];
        assert_eq!(&text[h.start..h.end], block);
    }

    #[test]
    fn a_last_key_line_followed_by_a_space_is_kept() {
        let mut g = Gen(61);
        let line = g.chars(AN, 40);
        let text = format!("-----BEGIN PRIVATE KEY-----\n{line} is my key");
        let h = &scan(&text)[0];
        assert_eq!(h.end, text.len() - " is my key".len());
    }

    fn outcome(content_type: &str, body: &[u8], on_hit: Verdict) -> Outcome {
        let policy = DirectionPolicy {
            on_hit,
            ..block_policy()
        };
        let meta = BodyMeta {
            content_type: Some(content_type),
            encoded: false,
        };
        apply(&policy, Direction::Request, meta, body)
    }

    fn token(seed: u64) -> String {
        format!("ghp_{}", Gen(seed).chars(AN, 36))
    }

    #[test]
    fn invalid_utf8_does_not_hide_a_secret() {
        let mut body = format!(r#"{{"q":"{}"}}"#, token(23)).into_bytes();
        body.push(0xFF);
        assert!(matches!(
            outcome("application/json", &body, Verdict::Block),
            Outcome::Block { .. }
        ));
    }

    #[test]
    fn escaped_key_in_unparseable_json_is_found() {
        // Trailing bytes make serde_json reject the body (Go's decoder
        // accepts it); the key is only visible after unescaping.
        let t = token(29);
        let body = format!("{{\"q\":\"\\u0067{}\"}} trailing", &t[1..]);
        assert!(body.contains("\\u0067hp_"));
        assert!(serde_json::from_str::<serde_json::Value>(&body).is_err());
        assert!(matches!(
            outcome("application/json", body.as_bytes(), Verdict::Block),
            Outcome::Block { .. }
        ));
    }

    #[test]
    fn a_key_escaped_inside_json_nested_in_a_string_is_found() {
        // AGENT-270: tool arguments are often JSON in a JSON string. Two
        // levels of escaping hide `g` behind `\\u0067`.
        let t = token(31);
        let inner = serde_json::json!({ "k": format!("\\u0067{}", &t[1..]) }).to_string();
        let body = serde_json::json!({ "args": inner }).to_string();
        assert!(!body.contains("ghp_"), "{body}");
        for verdict in [Verdict::Block, Verdict::Redact] {
            let out = outcome("application/json", body.as_bytes(), verdict);
            let Outcome::Block { report } = out else {
                panic!("{verdict:?}: forwarded");
            };
            assert!(
                report.hits.iter().any(|h| h.rule == "github_token"),
                "{report:?}"
            );
        }
    }

    #[test]
    fn a_private_key_in_nested_tool_arguments_still_redacts() {
        // Review finding: the deeper view turns the segment's `\n` into
        // a real newline, so the same key hashes differently there. It
        // must not count as a copy the rewrite can't reach.
        let mut g = Gen(37);
        let lines: Vec<String> = (0..4).map(|_| g.chars(AN, 64)).collect();
        let pem = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
            lines.join("\n")
        );
        let inner = serde_json::json!({ "key": pem }).to_string();
        let body = serde_json::json!({ "args": inner }).to_string();
        let out = outcome("application/json", body.as_bytes(), Verdict::Redact);
        let Outcome::Forward {
            body: Some(rewritten),
            report,
        } = out
        else {
            panic!("blocked instead of redacted");
        };
        let rewritten = String::from_utf8(rewritten).unwrap();
        assert!(!rewritten.contains(&lines[1]), "{rewritten}");
        assert!(rewritten.contains("[REDACTED:dlp]"), "{rewritten}");
        assert!(!report.redaction_incomplete);
    }

    #[test]
    fn nested_unescaping_stops_at_a_bounded_depth() {
        let views = super::super::text::nested_views(&"\\\\".repeat(64));
        assert_eq!(views.len(), super::super::text::NESTED_ESCAPE_DEPTH);
    }

    #[test]
    fn shadowed_duplicate_key_is_scanned() {
        let body = format!(r#"{{"q":"{}","q":"hi"}}"#, token(31));
        assert!(matches!(
            outcome("application/json", body.as_bytes(), Verdict::Block),
            Outcome::Block { .. }
        ));
        // AGENT-270: string tokens are rewritten in place, so the shadowed
        // copy is redacted too and the body keeps both keys.
        match outcome("application/json", body.as_bytes(), Verdict::Redact) {
            Outcome::Forward {
                body: Some(out), ..
            } => {
                let out = String::from_utf8(out).unwrap();
                assert!(!out.contains(&token(31)), "{out}");
                assert!(out.ends_with(r#","q":"hi"}"#), "{out}");
            }
            _ => panic!("expected a redacted forward"),
        }
    }

    #[test]
    fn form_encoded_key_is_found() {
        let t = token(37);
        let body = format!("a=1&q=gh%70{}&b=2", &t[3..]);
        assert!(matches!(
            outcome(
                "application/x-www-form-urlencoded",
                body.as_bytes(),
                Verdict::Block
            ),
            Outcome::Block { .. }
        ));
    }

    #[test]
    fn plain_json_redaction_still_rewrites() {
        let body = format!(r#"{{"q":"use {} now"}}"#, token(41));
        let Outcome::Forward {
            body: Some(out), ..
        } = outcome("application/json", body.as_bytes(), Verdict::Redact)
        else {
            panic!("expected a rewrite");
        };
        assert!(String::from_utf8(out).unwrap().contains("[REDACTED:dlp]"));
    }

    #[test]
    fn a_copy_left_after_redaction_blocks() {
        let t = token(43);
        let policy = DirectionPolicy {
            on_hit: Verdict::Redact,
            ..block_policy()
        };
        // The same key in the body and in the query: the body copy can be
        // redacted, the query copy cannot.
        let body = format!(r#"{{"q":"{t}"}}"#);
        let meta = BodyMeta {
            content_type: Some("application/json"),
            encoded: false,
        };
        let out = apply_with(
            &policy,
            Direction::Request,
            meta,
            body.as_bytes(),
            &[format!("k={t}")],
        );
        assert!(matches!(out, Outcome::Block { .. }), "query copy forwarded");
        // A plain and a percent-encoded copy in one form body.
        let form = format!("a={t}&b=gh%70{}", &t[3..]);
        assert!(matches!(
            outcome(
                "application/x-www-form-urlencoded",
                form.as_bytes(),
                Verdict::Redact
            ),
            Outcome::Block { .. }
        ));
    }

    /// AGENT-270/309: a key longer than 8 KiB (a long or heavily escaped
    /// key) is followed to its end, so no tail of it is forwarded.
    #[test]
    fn a_key_running_past_the_window_is_covered_to_the_end() {
        let line = "QUJD".repeat(16); // 64 base64 characters
        let body: String = (0..200).map(|_| format!("{line}\n")).collect();
        let text = format!("x -----BEGIN PRIVATE KEY-----\n{body}tail");
        assert!(text.len() > super::PEM_BODY_MAX);
        let (_, start, end) = super::rule_hits(&text)
            .into_iter()
            .find(|(id, ..)| *id == "private_key")
            .expect("private_key hit");
        assert_eq!(start, 2);
        assert_eq!(end, text.len(), "the key's tail must be covered");
    }

    /// AGENT-311: a key joined onto its BEGIN line with spaces (headers
    /// and base64 on one line), with no END within `PEM_BODY_MAX`, is
    /// covered to its last base64, not just its BEGIN line.
    #[test]
    fn a_space_joined_key_without_a_near_end_is_covered() {
        let words: Vec<String> = (0..200).map(|_| "QUJD".repeat(16)).collect();
        let body = words.join(" ");
        for (head, tail) in [
            (
                "-----BEGIN RSA PRIVATE KEY----- Proc-Type: 4,ENCRYPTED \
                 DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF ",
                " -----END RSA PRIVATE KEY-----",
            ),
            ("-----BEGIN PRIVATE KEY----- ", ". That is all."),
        ] {
            let text = format!("x {head}{body}{tail}");
            assert!(body.len() > super::PEM_BODY_MAX);
            let (_, start, end) = super::rule_hits(&text)
                .into_iter()
                .find(|(id, ..)| *id == "private_key")
                .expect("private_key hit");
            assert_eq!(start, 2);
            assert_eq!(end, 2 + head.len() + body.len(), "{head}");
        }
    }

    /// A key's first line on its BEGIN line (no space, or one space),
    /// then line after line, with no END within `PEM_BODY_MAX`: one word
    /// of base64 there is a key line however short, as before AGENT-311.
    #[test]
    fn a_first_key_line_on_the_begin_line_is_walked() {
        let line = "QUJD".repeat(16);
        let rest: String = (0..200).map(|_| format!("\n{line}")).collect();
        for joint in ["", " "] {
            let text = format!("x -----BEGIN PRIVATE KEY-----{joint}MIIE{rest}\n-- done");
            let (_, start, end) = super::rule_hits(&text)
                .into_iter()
                .find(|(id, ..)| *id == "private_key")
                .expect("private_key hit");
            assert_eq!(start, 2);
            assert_eq!(end, text.len() - "\n-- done".len(), "{joint:?}");
        }
    }

    /// RFC 1421 headers joined onto the BEGIN line, then the blank line,
    /// then the key, with no END within `PEM_BODY_MAX`; and a short key
    /// on the BEGIN line closed by a quote.
    #[test]
    fn headers_on_the_begin_line_then_a_blank_line_are_walked() {
        let line = "QUJD".repeat(16);
        let rest: String = (0..200).map(|_| format!("\n{line}")).collect();
        let text = format!(
            "x -----BEGIN RSA PRIVATE KEY----- Proc-Type: 4,ENCRYPTED \
             DEK-Info: AES-128-CBC,0011\n{rest}\n-- done"
        );
        let (_, _, end) = super::rule_hits(&text)
            .into_iter()
            .find(|(id, ..)| *id == "private_key")
            .expect("private_key hit");
        assert_eq!(end, text.len() - "\n-- done".len());
        let text = "x -----BEGIN PRIVATE KEY-----AB==\"} and more";
        let (_, _, end) = super::rule_hits(text)
            .into_iter()
            .find(|(id, ..)| *id == "private_key")
            .expect("private_key hit");
        assert_eq!(&text[end - 4..end], "AB==");
    }

    /// In a stream the text can stop inside a joined key's first word, or
    /// after a short word with long ones to come: the hit covers it and
    /// stays open.
    #[test]
    fn a_joined_key_cut_short_by_the_stream_stays_open() {
        let long = "QUJD".repeat(16);
        for cut in [
            "-----BEGIN PRIVATE KEY----- MIIEvQ".to_string(),
            format!("-----BEGIN PRIVATE KEY----- {long} AB {long} MI"),
            format!("-----BEGIN RSA PRIVATE KEY----- Proc-Type: 4,ENCRYPTED {long} AB"),
        ] {
            let text = format!("x {cut}");
            let hits = Dlp.scan(&text, Direction::Response).unwrap();
            let hit = hits
                .iter()
                .find(|h| h.rule == "private_key")
                .expect("private_key hit");
            assert_eq!(hit.end, text.len(), "{cut}");
            assert!(Dlp.holds_open(&text, hit), "{cut}");
        }
    }

    /// AGENT-311: a key closed by its END line is not held open, so blank
    /// padding after many BEGIN lines sharing one END isn't walked once per
    /// hit on every scan.
    #[test]
    fn a_key_closed_by_its_end_line_is_not_open() {
        // Within PEM_BODY_MAX of the END, so every hit ends at it.
        let begins = "-----BEGIN PRIVATE KEY-----\n".repeat(250);
        let text = format!(
            "{begins}QUJD\n-----END PRIVATE KEY-----{}",
            " ".repeat(4096)
        );
        let hits = Dlp.scan(&text, Direction::Response).unwrap();
        let keys: Vec<_> = hits.iter().filter(|h| h.rule == "private_key").collect();
        assert_eq!(keys.len(), 250);
        assert!(keys.iter().all(|h| h.end == keys[0].end));
        assert!(keys.iter().all(|h| !Dlp.holds_open(&text, h)));
    }

    /// A hit that is still only its BEGIN line (the key not yet streamed)
    /// ends with "PRIVATE KEY-----" too, and must stay open.
    #[test]
    fn a_begin_line_with_its_key_still_to_come_is_open() {
        for text in [
            "x -----BEGIN PRIVATE KEY-----",
            "x -----BEGIN RSA PRIVATE KEY-----\n",
            "x -----BEGIN PRIVATE KEY-----\\n  ",
        ] {
            let hits = Dlp.scan(text, Direction::Response).unwrap();
            let key = hits.iter().find(|h| h.rule == "private_key").expect("hit");
            assert!(Dlp.holds_open(text, key), "{text:?}");
        }
    }

    #[test]
    fn a_key_that_has_ended_is_not_open() {
        let key = format!("-----BEGIN PRIVATE KEY-----\n{}", "QUJD".repeat(16));
        for after in ["\n-- prose", "\"}", "\n\n\nmore", "  x", "\\x and more"] {
            let text = format!("{key}{after}");
            let (_, _, end) = super::rule_hits(&text)
                .into_iter()
                .find(|(id, ..)| *id == "private_key")
                .expect("private_key hit");
            assert!(!super::pem_open(&text, end), "after {after:?}");
        }
    }

    /// AGENT-311: an END line closes a key only where the walk would stop
    /// at it. A header line longer than the END search that ends in END
    /// text is walked past, so in a stream the key lines after it are
    /// still to come and the hit must stay open.
    #[test]
    fn a_header_line_ending_in_end_text_does_not_close_its_key() {
        let header = format!("Proc-Type: 4,{}", "x".repeat(super::PEM_BODY_MAX));
        let text = format!("-----BEGIN PRIVATE KEY-----\n{header}-----END PRIVATE KEY-----");
        let hits = Dlp.scan(&text, Direction::Response).unwrap();
        let key = hits.iter().find(|h| h.rule == "private_key").expect("hit");
        assert_eq!(key.end, text.len());
        assert!(Dlp.holds_open(&text, key));
    }

    /// AGENT-309: wherever a stream's text stops inside a key (mid-line,
    /// mid-escape, after a line break or indentation), its hit is still
    /// open, so the window holds it.
    #[test]
    fn text_ending_anywhere_in_a_key_leaves_its_hit_open() {
        for sep in [
            "\\n",
            "\\r\\n",
            "\\\\r\\\\n",
            "\\u000d\\u000a",
            " \\n",
            "\\t\\n",
            "\n",
            "\r\n",
        ] {
            for lead in ["", "\\/", "\\t", "\\u0020", "  "] {
                let line = format!("{lead}{}{sep}", "QUJD".repeat(16));
                let full = format!("-----BEGIN PRIVATE KEY-----{sep}{}", line.repeat(3));
                for cut in full.len() - 2 * line.len()..=full.len() {
                    let text = &full[..cut];
                    let (_, _, end) = super::rule_hits(text)
                        .into_iter()
                        .find(|(id, ..)| *id == "private_key")
                        .expect("private_key hit");
                    assert!(
                        super::pem_open(text, end),
                        "sep {sep:?} lead {lead:?} cut {cut} end {end}"
                    );
                }
            }
        }
    }

    #[test]
    fn prose_on_a_long_begin_line_is_not_taken_for_a_key() {
        let text = format!("-----BEGIN PRIVATE KEY----- and {}", "so on ".repeat(2000));
        let (_, _, end) = super::rule_hits(&text)
            .into_iter()
            .find(|(id, ..)| *id == "private_key")
            .expect("private_key hit");
        assert!(end < 64, "end {end}");
    }

    #[test]
    fn an_outsized_key_in_a_json_string_is_redacted() {
        let line = "QUJD".repeat(16);
        let pem: String = (0..200).map(|_| format!("{line}\n")).collect();
        let body = serde_json::json!({
            "k": format!("-----BEGIN PRIVATE KEY-----\n{pem}"),
            "other": "hello",
        })
        .to_string();
        let Outcome::Forward {
            body: Some(rewritten),
            report,
        } = outcome("application/json", body.as_bytes(), Verdict::Redact)
        else {
            panic!("an outsized key in JSON must be redacted, not blocked or forwarded");
        };
        let rewritten = String::from_utf8(rewritten).unwrap();
        assert!(!rewritten.contains(&line), "{rewritten}");
        assert!(rewritten.contains("\"other\":\"hello\""), "{rewritten}");
        assert!(!report.redaction_incomplete);
    }

    #[test]
    fn begin_lines_packed_on_one_line_scan_in_linear_time() {
        for unit in [
            "-----BEGIN PRIVATE KEY-----QUJD",
            "-----BEGIN PRIVATE KEY-----\nDEK-Info: ",
            "-----BEGIN PRIVATE KEY----- \\",
            "-----BEGIN RSA PRIVATE KEY----- Proc-Type: 4,ENCRYPTED DEK-Info: AES-128-CBC,AB ",
            "-----BEGIN PRIVATE KEY----- QUJD QUJD ",
        ] {
            let text = unit.repeat((1 << 20) / unit.len());
            let started = std::time::Instant::now();
            let hits = super::rule_hits(&text);
            assert!(hits.len() > 1000);
            let took = started.elapsed();
            assert!(took.as_secs() < 5, "{unit:?} took {took:?}");
        }
    }

    #[test]
    fn every_cut_position_inside_a_key_line_fails_safe() {
        for sep in [
            "\\n",
            "\\r\\n",
            "\\\\r\\\\n",
            "\\u000d\\u000a",
            " \\n",
            "\\t\\n",
            "\n",
            "\r\n",
        ] {
            let line = format!("{}{sep}", "QUJD".repeat(16));
            let body = line.repeat(200);
            for shift in 0..line.len() {
                let pad = " ".repeat(shift + 1);
                let text = format!("-----BEGIN PRIVATE KEY-----{pad}{sep}{body}end");
                let (_, _, end) = super::rule_hits(&text)
                    .into_iter()
                    .find(|(id, ..)| *id == "private_key")
                    .expect("private_key hit");
                assert_eq!(end, text.len(), "sep {sep:?} shift {shift}");
            }
        }
    }

    #[test]
    fn a_key_past_the_window_ends_at_its_last_line() {
        let line = "QUJD".repeat(16);
        for n in [126, 200] {
            let body: String = (0..n).map(|_| format!("{line}\n")).collect();
            let text = format!(
                "-----BEGIN PRIVATE KEY----- \n{body}-- prose {}",
                "x".repeat(9000)
            );
            let (_, _, end) = super::rule_hits(&text)
                .into_iter()
                .find(|(id, ..)| *id == "private_key")
                .expect("private_key hit");
            assert_eq!(&text[end..end + 9], "\n-- prose", "n {n}");
        }
    }

    #[test]
    fn a_key_ending_inside_the_window_is_not_extended() {
        let line = "QUJD".repeat(16);
        let body: String = (0..20).map(|_| format!("{line}\n")).collect();
        let text = format!(
            "-----BEGIN PRIVATE KEY-----\n{body}-- prose{}",
            " ".repeat(9000)
        );
        let (_, _, end) = super::rule_hits(&text)
            .into_iter()
            .find(|(id, ..)| *id == "private_key")
            .expect("private_key hit");
        assert_eq!(&text[end - 4..end], "QUJD", "ends at the last key line");
    }
}
