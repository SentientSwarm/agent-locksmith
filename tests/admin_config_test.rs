//! Admin substrate config fields (M2 wiring).
//!
//! Adds `listen.admin_socket.path` and top-level `operator_credentials_path`
//! to AppConfig so `main.rs` can wire `admin::uds::bind_and_serve` from
//! YAML. Both fields are optional: when both are absent, the daemon runs
//! without an admin UDS (M0/M1 backward compat). When `admin_socket.path`
//! is set, `operator_credentials_path` is required at startup (validated
//! by main.rs, not by serde).

use agent_locksmith::config::parse_config_str;

#[test]
fn admin_socket_and_operator_creds_parse() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
  admin_socket:
    path: "/var/run/locksmith/admin.sock"
operator_credentials_path: "/etc/locksmith/operators.yaml"
tools: []
"#;
    let cfg = parse_config_str(yaml).expect("parse succeeds with admin substrate fields");
    let admin = cfg
        .listen
        .admin_socket
        .as_ref()
        .expect("admin_socket present");
    assert_eq!(
        admin.path.to_string_lossy(),
        "/var/run/locksmith/admin.sock"
    );
    assert_eq!(
        cfg.operator_credentials_path
            .as_ref()
            .expect("operator_credentials_path present")
            .to_string_lossy(),
        "/etc/locksmith/operators.yaml"
    );
}

#[test]
fn admin_substrate_fields_are_optional() {
    // M0/M1 deployments without admin substrate must keep working.
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let cfg = parse_config_str(yaml).expect("M0/M1 config parses");
    assert!(cfg.listen.admin_socket.is_none());
    assert!(cfg.operator_credentials_path.is_none());
}

#[test]
fn admin_socket_unknown_field_rejected() {
    // deny_unknown_fields must apply to the new nested struct too.
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
  admin_socket:
    path: "/tmp/x.sock"
    bogus: 1
tools: []
"#;
    let err = parse_config_str(yaml).expect_err("unknown admin_socket field rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("bogus") || msg.contains("unknown"),
        "error should name the unknown field; got: {msg}"
    );
}
