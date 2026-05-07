//! T7.1 — `tools[].response` config block parses + validates.

use agent_locksmith::config::parse_config_str;

#[test]
fn response_block_absent_yields_default() {
    let cfg = parse_config_str(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: t
    description: t
    upstream: "https://example.com"
"#,
    )
    .unwrap();
    assert!(cfg.tools[0].response.is_none());
}

#[test]
fn response_block_full_shape() {
    let cfg = parse_config_str(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: t
    description: t
    upstream: "https://example.com"
    response:
      max_size_bytes: 1048576
      content_type_allowlist: ["application/json", "text/event-stream"]
      redaction_patterns:
        - id: openai_key
          regex: "sk-[A-Za-z0-9]{20,}"
        - id: aws_secret
          regex: "AKIA[A-Z0-9]{16}"
          replacement: "[AWS-KEY-REDACTED]"
"#,
    )
    .unwrap();
    let r = cfg.tools[0].response.as_ref().unwrap();
    assert_eq!(r.max_size_bytes, Some(1_048_576));
    assert_eq!(
        r.content_type_allowlist.as_deref(),
        Some(
            &[
                "application/json".to_string(),
                "text/event-stream".to_string()
            ][..]
        )
    );
    let patterns = &r.redaction_patterns;
    assert_eq!(patterns.len(), 2);
    assert_eq!(patterns[0].id, "openai_key");
    assert_eq!(patterns[0].replacement.as_deref(), None);
    assert_eq!(patterns[1].id, "aws_secret");
    assert_eq!(
        patterns[1].replacement.as_deref(),
        Some("[AWS-KEY-REDACTED]")
    );
}

#[test]
fn invalid_redaction_regex_fails_config_load() {
    let err = parse_config_str(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: t
    description: t
    upstream: "https://example.com"
    response:
      redaction_patterns:
        - id: bad
          regex: "[unclosed"
"#,
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("regex") || msg.contains("redaction"),
        "error names the bad regex; got: {msg}"
    );
}

#[test]
fn duplicate_pattern_id_fails_config_load() {
    let err = parse_config_str(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: t
    description: t
    upstream: "https://example.com"
    response:
      redaction_patterns:
        - id: dup
          regex: "a"
        - id: dup
          regex: "b"
"#,
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("duplicate") || msg.contains("dup"),
        "error names the duplicate pattern id; got: {msg}"
    );
}
