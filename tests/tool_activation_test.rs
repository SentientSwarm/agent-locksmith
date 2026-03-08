use agent_locksmith::config::AppConfig;

#[test]
fn test_active_tools_filters_empty_credentials() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "github"
    description: "GitHub"
    upstream: "https://api.github.com"
    auth:
      header: "Authorization"
      value: "Bearer real-token"
    timeout_seconds: 30
  - name: "tavily"
    description: "Tavily"
    upstream: "https://api.tavily.com"
    auth:
      header: "x-api-key"
      value: ""
    timeout_seconds: 15
  - name: "noauth"
    description: "No auth tool"
    upstream: "https://example.com"
    timeout_seconds: 10
"#;
    let config: AppConfig = serde_yaml::from_str(yaml).unwrap();
    let active = config.active_tools();
    assert_eq!(active.len(), 2);
    assert_eq!(active[0].name, "github");
    assert_eq!(active[1].name, "noauth");
}
