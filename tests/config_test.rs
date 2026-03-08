use secure_agent_proxy::config::AppConfig;

#[test]
fn test_parse_minimal_config() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub REST API"
    upstream: "https://api.github.com"
    cloud: true
    auth:
      header: "Authorization"
      value: "Bearer test-token-123"
    timeout_seconds: 30
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.listen.port, 9200);
    assert_eq!(config.tools.len(), 1);
    assert_eq!(config.tools[0].name, "github");
    assert_eq!(config.tools[0].upstream, "https://api.github.com");
    assert!(config.tools[0].cloud);
}

#[test]
fn test_empty_tools_list() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.tools.is_empty());
}

#[test]
fn test_optional_fields_default() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.egress_proxy.is_none());
    assert!(config.inbound_auth.is_none());
    assert!(config.telemetry.is_none());
    assert!(config.logging.is_none());
}
