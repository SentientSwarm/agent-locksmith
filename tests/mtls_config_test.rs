//! T6.6 — auth_mode + mtls config block parses.

use agent_locksmith::config::{AuthMode, parse_config_str};

#[test]
fn auth_mode_defaults_to_bearer() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let cfg = parse_config_str(yaml).unwrap();
    assert_eq!(cfg.listen.auth_mode, AuthMode::Bearer);
    assert!(cfg.listen.mtls.is_none());
}

#[test]
fn auth_mode_mtls_with_full_block() {
    let yaml = r#"
listen:
  host: "0.0.0.0"
  port: 9200
  auth_mode: mtls
  mtls:
    ca_bundle_path: "/etc/locksmith/agents-ca.crt"
    crl_url: "https://ca.example.com/crl.pem"
    crl_refresh_interval_seconds: 600
    blocklist_path: "/var/lib/locksmith/mtls-blocklist"
tools: []
"#;
    let cfg = parse_config_str(yaml).unwrap();
    assert_eq!(cfg.listen.auth_mode, AuthMode::Mtls);
    let mtls = cfg.listen.mtls.expect("mtls block parses");
    assert_eq!(
        mtls.ca_bundle_path.to_str().unwrap(),
        "/etc/locksmith/agents-ca.crt"
    );
    assert_eq!(
        mtls.crl_url.as_deref(),
        Some("https://ca.example.com/crl.pem")
    );
    assert_eq!(mtls.crl_refresh_interval_seconds, 600);
    assert_eq!(mtls.blocklist_reload_interval_seconds, 30);
}

#[test]
fn auth_mode_both_minimum_block() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
  auth_mode: both
  mtls:
    ca_bundle_path: "/etc/locksmith/ca.crt"
tools: []
"#;
    let cfg = parse_config_str(yaml).unwrap();
    assert_eq!(cfg.listen.auth_mode, AuthMode::Both);
    let mtls = cfg.listen.mtls.unwrap();
    // Defaults populated.
    assert_eq!(mtls.crl_refresh_interval_seconds, 3600);
    assert!(mtls.crl_url.is_none());
    assert!(mtls.blocklist_path.is_none());
}

#[test]
fn invalid_auth_mode_rejected() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
  auth_mode: vibes
tools: []
"#;
    let err = parse_config_str(yaml).unwrap_err();
    assert!(format!("{err}").contains("auth_mode") || format!("{err}").contains("variant"));
}
