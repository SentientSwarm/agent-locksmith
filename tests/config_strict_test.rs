//! T1.6 + T1.7 — `egress` enum, deny_unknown_fields strict parsing, and
//! deprecation interception (cloud → egress, telemetry removed).
//!
//! Covers: R-F2, R-F13, R-N5, INF-15, INF-17, INF-24.

use agent_locksmith::config::{EgressMode, parse_config_str};

#[test]
fn test_egress_direct_parses() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "lmstudio"
    description: "Local LM Studio"
    upstream: "http://localhost:1234"
    egress: "direct"
    timeout_seconds: 30
"#;
    let config = parse_config_str(yaml).expect("parse succeeds");
    assert_eq!(config.tools[0].egress, EgressMode::Direct);
}

#[test]
fn test_egress_proxied_parses() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "anthropic"
    description: "Anthropic"
    upstream: "https://api.anthropic.com"
    egress: "proxied"
    timeout_seconds: 30
"#;
    let config = parse_config_str(yaml).expect("parse succeeds");
    assert_eq!(config.tools[0].egress, EgressMode::Proxied);
}

#[test]
fn test_egress_default_when_omitted() {
    // Preserves M0 default behavior (M0's cloud default was false → no egress
    // proxy). v2 default: EgressMode::Direct.
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "x"
    description: "x"
    upstream: "http://x"
    timeout_seconds: 30
"#;
    let config = parse_config_str(yaml).expect("parse succeeds");
    assert_eq!(config.tools[0].egress, EgressMode::Direct);
}

#[test]
fn test_egress_typo_rejected() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "x"
    description: "x"
    upstream: "http://x"
    egress: "directt"
    timeout_seconds: 30
"#;
    let err = parse_config_str(yaml).expect_err("typo'd egress value rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("egress") || msg.contains("directt"),
        "error should mention the offending field or value; got: {msg}"
    );
}

#[test]
fn test_unknown_top_level_field_rejected() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
made_up_field: "ignored"
tools: []
"#;
    let err = parse_config_str(yaml).expect_err("unknown top-level field rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("made_up_field") || msg.contains("unknown"),
        "error should name the unknown field; got: {msg}"
    );
}

#[test]
fn test_unknown_tool_field_rejected() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "x"
    description: "x"
    upstream: "http://x"
    egress: "direct"
    bogus_field: 42
    timeout_seconds: 30
"#;
    let err = parse_config_str(yaml).expect_err("unknown tool field rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("bogus_field") || msg.contains("unknown"),
        "error should name the unknown field; got: {msg}"
    );
}

#[test]
fn test_legacy_cloud_true_maps_to_egress_proxied() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub"
    upstream: "https://api.github.com"
    cloud: true
    timeout_seconds: 30
"#;
    let config = parse_config_str(yaml).expect("legacy cloud field translated, not rejected");
    assert_eq!(config.tools[0].egress, EgressMode::Proxied);
}

#[test]
fn test_legacy_cloud_false_maps_to_egress_direct() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "lmstudio"
    description: "Local"
    upstream: "http://localhost:1234"
    cloud: false
    timeout_seconds: 30
"#;
    let config = parse_config_str(yaml).expect("legacy cloud=false translated to direct");
    assert_eq!(config.tools[0].egress, EgressMode::Direct);
}

#[test]
fn test_legacy_telemetry_block_warned_and_ignored() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
telemetry:
  enabled: true
  otlp_endpoint: "http://otel:4317"
  service_name: "locksmith"
tools: []
"#;
    // The deprecated `telemetry:` block must be accepted (translated to a
    // no-op) rather than rejected. OTel was deferred per Q-19; the field
    // is M0 dead code being phased out under INF-24.
    let config = parse_config_str(yaml).expect("legacy telemetry block warned and ignored");
    assert!(config.tools.is_empty());
}

#[test]
fn test_per_tool_timeouts_parse() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "anthropic"
    description: "Anthropic"
    upstream: "https://api.anthropic.com"
    egress: "proxied"
    timeouts:
      request_seconds: 600
      idle_seconds: 90
    body_limit_bytes: 20971520
"#;
    let config = parse_config_str(yaml).expect("new shape parses");
    let tool = &config.tools[0];
    assert_eq!(tool.timeouts.request_seconds, 600);
    assert_eq!(tool.timeouts.idle_seconds, 90);
    assert_eq!(tool.body_limit_bytes, 20_971_520);
}

#[test]
fn test_per_tool_timeouts_default_when_omitted() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "x"
    description: "x"
    upstream: "http://x"
    egress: "direct"
"#;
    let config = parse_config_str(yaml).expect("defaults apply");
    let tool = &config.tools[0];
    assert_eq!(tool.timeouts.request_seconds, 30);
    assert_eq!(tool.timeouts.idle_seconds, 60);
    assert_eq!(tool.body_limit_bytes, 10_485_760);
}

#[test]
fn test_legacy_timeout_seconds_renamed_to_request_seconds() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "x"
    description: "x"
    upstream: "http://x"
    egress: "direct"
    timeout_seconds: 600
"#;
    let config = parse_config_str(yaml).expect("legacy timeout_seconds translated");
    let tool = &config.tools[0];
    assert_eq!(
        tool.timeouts.request_seconds, 600,
        "legacy timeout_seconds maps to timeouts.request_seconds"
    );
    assert_eq!(
        tool.timeouts.idle_seconds, 60,
        "idle_seconds takes its default when only the legacy field is set"
    );
}

#[test]
fn test_explicit_timeouts_take_precedence_over_legacy_timeout_seconds() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "x"
    description: "x"
    upstream: "http://x"
    egress: "direct"
    timeout_seconds: 30
    timeouts:
      request_seconds: 600
      idle_seconds: 90
"#;
    let config = parse_config_str(yaml).expect("disagreement is non-fatal; explicit wins");
    assert_eq!(config.tools[0].timeouts.request_seconds, 600);
    assert_eq!(config.tools[0].timeouts.idle_seconds, 90);
}

#[test]
fn test_explicit_egress_takes_precedence_over_legacy_cloud() {
    // If both old and new fields are present and disagree, the new field
    // wins. Operators mid-migration who left `cloud:` in place but added
    // `egress:` get the explicit egress.
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "x"
    description: "x"
    upstream: "http://x"
    cloud: false
    egress: "proxied"
    timeout_seconds: 30
"#;
    let config = parse_config_str(yaml).expect("disagreement is non-fatal; egress wins");
    assert_eq!(config.tools[0].egress, EgressMode::Proxied);
}
