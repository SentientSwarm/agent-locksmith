//! T7.2 — ResponseControls.apply for non-streaming responses.

use agent_locksmith::config::{RedactionPatternConfig, ResponseControlsConfig};
use agent_locksmith::response_controls::{ApplyOutcome, ResponseControls};

fn from_cfg(cfg: ResponseControlsConfig) -> ResponseControls {
    ResponseControls::compile(&cfg).expect("compile ok")
}

#[test]
fn passes_through_when_no_controls() {
    let rc = ResponseControls::compile(&ResponseControlsConfig {
        max_size_bytes: None,
        content_type_allowlist: None,
        redaction_patterns: vec![],
    })
    .unwrap();
    let body = b"hello world".to_vec();
    let outcome = rc.apply_non_streaming(Some("text/plain"), body.clone());
    match outcome {
        ApplyOutcome::Allowed {
            body: b,
            redactions,
        } => {
            assert_eq!(b, body);
            assert!(redactions.is_empty());
        }
        other => panic!("expected Allowed, got {other:?}"),
    }
}

#[test]
fn rejects_oversize_non_streaming() {
    let rc = from_cfg(ResponseControlsConfig {
        max_size_bytes: Some(10),
        content_type_allowlist: None,
        redaction_patterns: vec![],
    });
    let body = vec![b'x'; 100];
    let outcome = rc.apply_non_streaming(Some("text/plain"), body);
    assert!(
        matches!(outcome, ApplyOutcome::SizeExceeded { observed, cap } if observed == 100 && cap == 10),
        "got: {outcome:?}"
    );
}

#[test]
fn allows_at_cap_non_streaming() {
    let rc = from_cfg(ResponseControlsConfig {
        max_size_bytes: Some(10),
        content_type_allowlist: None,
        redaction_patterns: vec![],
    });
    let body = vec![b'x'; 10];
    let outcome = rc.apply_non_streaming(Some("text/plain"), body);
    assert!(matches!(outcome, ApplyOutcome::Allowed { .. }));
}

#[test]
fn allowlist_strips_charset_suffix() {
    let rc = from_cfg(ResponseControlsConfig {
        max_size_bytes: None,
        content_type_allowlist: Some(vec!["application/json".into()]),
        redaction_patterns: vec![],
    });
    let outcome = rc.apply_non_streaming(Some("application/json; charset=utf-8"), b"{}".to_vec());
    assert!(matches!(outcome, ApplyOutcome::Allowed { .. }));
}

#[test]
fn allowlist_rejects_disallowed_content_type() {
    let rc = from_cfg(ResponseControlsConfig {
        max_size_bytes: None,
        content_type_allowlist: Some(vec!["application/json".into()]),
        redaction_patterns: vec![],
    });
    let outcome = rc.apply_non_streaming(Some("text/html"), b"<html/>".to_vec());
    assert!(
        matches!(&outcome, ApplyOutcome::ContentTypeDisallowed { observed } if observed == "text/html"),
        "got: {outcome:?}"
    );
}

#[test]
fn allowlist_rejects_missing_content_type() {
    let rc = from_cfg(ResponseControlsConfig {
        max_size_bytes: None,
        content_type_allowlist: Some(vec!["application/json".into()]),
        redaction_patterns: vec![],
    });
    let outcome = rc.apply_non_streaming(None, b"{}".to_vec());
    assert!(matches!(
        outcome,
        ApplyOutcome::ContentTypeDisallowed { .. }
    ));
}

#[test]
fn redaction_replaces_match_with_default_marker() {
    let rc = from_cfg(ResponseControlsConfig {
        max_size_bytes: None,
        content_type_allowlist: None,
        redaction_patterns: vec![RedactionPatternConfig {
            id: "openai_key".into(),
            regex: r"sk-[A-Za-z0-9]{6,}".into(),
            replacement: None,
        }],
    });
    let body = b"token=sk-ABCDEF123 ok".to_vec();
    let outcome = rc.apply_non_streaming(Some("text/plain"), body);
    match outcome {
        ApplyOutcome::Allowed { body, redactions } => {
            let s = String::from_utf8(body).unwrap();
            assert!(!s.contains("sk-ABCDEF123"));
            assert!(s.contains("[REDACTED:openai_key]"));
            assert_eq!(redactions.len(), 1);
            assert_eq!(redactions[0].pattern_id, "openai_key");
            assert_eq!(redactions[0].matches, 1);
            // Hash is hex of sha256 of cleartext; just sanity-check it's
            // populated and not the cleartext itself.
            assert!(!redactions[0].match_hash.contains("sk-ABCDEF123"));
            assert_eq!(redactions[0].match_hash.len(), 64);
        }
        other => panic!("expected Allowed, got {other:?}"),
    }
}

#[test]
fn redaction_uses_custom_replacement_when_provided() {
    let rc = from_cfg(ResponseControlsConfig {
        max_size_bytes: None,
        content_type_allowlist: None,
        redaction_patterns: vec![RedactionPatternConfig {
            id: "aws".into(),
            regex: r"AKIA[A-Z0-9]{16}".into(),
            replacement: Some("[AWS-KEY]".into()),
        }],
    });
    let body = b"key=AKIAABCDEFGHIJKLMNOP done".to_vec();
    let outcome = rc.apply_non_streaming(Some("text/plain"), body);
    match outcome {
        ApplyOutcome::Allowed { body, .. } => {
            let s = String::from_utf8(body).unwrap();
            assert!(s.contains("[AWS-KEY]"));
            assert!(!s.contains("AKIAABCDEFGHIJKLMNOP"));
        }
        other => panic!("expected Allowed, got {other:?}"),
    }
}

#[test]
fn redaction_counts_multiple_matches_per_pattern() {
    let rc = from_cfg(ResponseControlsConfig {
        max_size_bytes: None,
        content_type_allowlist: None,
        redaction_patterns: vec![RedactionPatternConfig {
            id: "ssn".into(),
            regex: r"\d{3}-\d{2}-\d{4}".into(),
            replacement: None,
        }],
    });
    let body = b"123-45-6789 and 987-65-4321 found".to_vec();
    let outcome = rc.apply_non_streaming(Some("text/plain"), body);
    match outcome {
        ApplyOutcome::Allowed { redactions, .. } => {
            assert_eq!(redactions.len(), 1);
            assert_eq!(redactions[0].matches, 2);
        }
        other => panic!("expected Allowed, got {other:?}"),
    }
}

#[test]
fn redaction_skips_when_body_not_utf8() {
    let rc = from_cfg(ResponseControlsConfig {
        max_size_bytes: None,
        content_type_allowlist: None,
        redaction_patterns: vec![RedactionPatternConfig {
            id: "x".into(),
            regex: r"x".into(),
            replacement: None,
        }],
    });
    let body = vec![0xff, 0xfe, 0xfd]; // not valid UTF-8
    let outcome = rc.apply_non_streaming(Some("application/octet-stream"), body.clone());
    match outcome {
        ApplyOutcome::Allowed {
            body: b,
            redactions,
        } => {
            assert_eq!(b, body);
            assert!(redactions.is_empty(), "no regex application on non-UTF8");
        }
        other => panic!("expected Allowed, got {other:?}"),
    }
}
