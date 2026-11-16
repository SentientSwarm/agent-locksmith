//! AGENT-263 — `dlp`: credential and secret patterns.
//!
//! Locksmith's own curated rules (not a port of another tool's set). Every
//! rule has a fixed upper bound on what it can match, which streaming
//! scanning uses as its window overlap. Base64 runs of 24..=4096 characters
//! are decoded once and the decoded text scanned with the same rules, so an
//! encoded key is still found. A Shannon-entropy heuristic catches unknown
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
    /// Grows a match past what the pattern matched (text, match end).
    extend: Option<fn(&str, usize) -> usize>,
}

fn rule(id: &'static str, pattern: &str, max_len: usize, check: Option<fn(&str) -> bool>) -> Rule {
    Rule {
        id,
        re: Regex::new(pattern).expect("dlp rule compiles"),
        max_len,
        check,
        extend: None,
    }
}

/// Longest PEM body (between the BEGIN and END lines) redacted as one key.
const PEM_BODY_MAX: usize = 8192;
const PEM_HEADER_MAX: usize = 47;

static PEM_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)-----END [A-Z ]{0,20}PRIVATE KEY-----").expect("compiles"));

/// The whole PEM block after a BEGIN line: through the END line, or, with
/// no END in reach, through the base64 and RFC 1421 header lines that
/// follow. Redacting only the BEGIN line would leave the key.
fn pem_extend(text: &str, header_end: usize) -> usize {
    let rest = &text[header_end..];
    let mut limit = rest.len().min(PEM_BODY_MAX);
    while !rest.is_char_boundary(limit) {
        limit -= 1;
    }
    let window = &rest[..limit];
    if let Some(m) = PEM_END.find(window) {
        return header_end + m.end();
    }
    let mut end = 0;
    let mut offset = 0;
    let mut after_header = false;
    for (i, line) in window.split('\n').enumerate() {
        let t = line.trim_end_matches('\r');
        let base64 = !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b));
        let header = t.starts_with("Proc-Type:") || t.starts_with("DEK-Info:");
        if base64 || header {
            end = offset + t.len();
            after_header = header;
        } else {
            // The rest of the BEGIN line, or the blank line after RFC 1421
            // headers, is skipped; anything else ends the block.
            let skippable = (i == 0 && t.trim().is_empty()) || (t.is_empty() && after_header);
            if skippable {
                offset += line.len() + 1;
                continue;
            }
            break;
        }
        offset += line.len() + 1;
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
                r"(?-u)-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----",
                PEM_HEADER_MAX + PEM_BODY_MAX,
                None,
            )
        },
        rule(
            "jwt",
            r"(?-u)\beyJ[A-Za-z0-9_-]{5,2048}\.[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{5,1024}",
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
    for r in RULES.iter() {
        for caps in r.re.captures_iter(text) {
            let m = caps.get(1).or_else(|| caps.get(0)).expect("group 0");
            if m.len() <= r.max_len && r.check.is_none_or(|c| c(m.as_str())) {
                let end = r.extend.map_or(m.end(), |grow| grow(text, m.end()));
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
        let Ok(decoded) = LENIENT_BASE64.decode(body) else {
            continue;
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            continue;
        };
        if let Some((id, ..)) = rule_hits(&decoded).first() {
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
    fn shadowed_duplicate_key_is_scanned() {
        let body = format!(r#"{{"q":"{}","q":"hi"}}"#, token(31));
        assert!(matches!(
            outcome("application/json", body.as_bytes(), Verdict::Block),
            Outcome::Block { .. }
        ));
        // It can't be redacted where the parser can't see it: block.
        assert!(matches!(
            outcome("application/json", body.as_bytes(), Verdict::Redact),
            Outcome::Block { report } if report.verdict == Verdict::Block
        ));
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
}
