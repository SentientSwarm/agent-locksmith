use agent_locksmith::{
    config::{EgressMode, parse_config_str},
    registrations::{Kind, McpConfig, Protocol, protocol},
};
use serde_json::json;
fn config() -> McpConfig {
    McpConfig {
        protocol_version: "2025-11-25".into(),
        allow_private_destination: false,
    }
}
fn valid(
    c: &McpConfig,
    kind: Kind,
    egress: EgressMode,
    url: &str,
    metadata: Option<&serde_json::Value>,
) -> bool {
    protocol::validate(
        Protocol::McpStreamableHttp,
        Some(c),
        kind,
        egress,
        url,
        metadata,
    )
    .is_ok()
}
#[test]
fn native_destination_refuses_invalid_or_unapproved_private_urls() {
    for url in [
        "http://example.com/mcp",
        "https://localhost/mcp",
        "https://localhost./mcp",
        "https://127.0.0.1/mcp",
        "https://[::1]/mcp",
        "https://user@example.com/mcp",
        "https://example.com/mcp?q=1",
        "https://example.com/mcp#fragment",
    ] {
        assert!(!valid(&config(), Kind::Tool, EgressMode::Direct, url, None));
    }
}
#[test]
fn native_kind_egress_and_http_metadata_are_not_interchangeable() {
    let c = config();
    let url = "https://example.com/mcp";
    for kind in [Kind::Model, Kind::Infra] {
        assert!(!valid(&c, kind, EgressMode::Direct, url, None));
    }
    assert!(!valid(&c, Kind::Tool, EgressMode::Proxied, url, None));
}
#[test]
fn native_metadata_and_private_approval_are_explicit() {
    let c = config();
    let url = "https://example.com/mcp";
    assert!(!valid(
        &c,
        Kind::Tool,
        EgressMode::Direct,
        url,
        Some(&json!({"http_service":{}}))
    ));
    assert!(valid(
        &c,
        Kind::Tool,
        EgressMode::Direct,
        "https://example.com/base/mcp",
        None
    ));
}
#[test]
fn private_destination_opt_in_retains_self_endpoint_refusal() {
    let c = McpConfig {
        allow_private_destination: true,
        ..config()
    };
    assert!(valid(
        &c,
        Kind::Tool,
        EgressMode::Direct,
        "https://[::1]/mcp",
        None
    ));
    assert!(protocol::is_self(
        "https://localhost:9200/mcp",
        "127.0.0.1",
        9200
    ));
}
#[test]
fn finite_native_config_rejects_zero_and_over_ceiling() {
    for field in [
        "ingress",
        "sessions",
        "sessions_per_agent",
        "sessions_per_connection",
        "messages",
        "streams",
        "handshake_ms",
        "lifetime_ms",
        "idle_ms",
        "request_ms",
        "response_ms",
        "request_bytes",
    ] {
        for value in [0, 1_000_000_000] {
            assert!(
                parse_config_str(&format!("listen:\n  port: 9200\nmcp:\n  {field}: {value}"))
                    .is_err()
            );
        }
    }
}
#[test]
fn native_config_rejects_unknown_fields_and_origin_wildcards() {
    for suffix in [
        "unknown: true",
        "allowed_hosts: ['*']",
        "allowed_origins: ['https://*.example']",
        "allowed_origins: ['https://user@example.com']",
        "allowed_origins: ['https://example.com/path']",
    ] {
        assert!(parse_config_str(&format!("listen:\n  port: 9200\nmcp:\n  {suffix}")).is_err());
    }
    assert!(
        serde_json::from_value::<McpConfig>(
            json!({"protocol_version":"2025-11-25","secret":"forbidden"})
        )
        .is_err()
    );
}
#[tokio::test]
async fn later_invalid_native_seed_preserves_earlier_rows_and_version() {
    use agent_locksmith::{
        migrations,
        registrations::{RegistrationRepository, seed_loader},
    };
    let dir = tempfile::tempdir().unwrap();
    let pool = migrations::open_and_migrate(&dir.path().join("state.db"))
        .await
        .unwrap();
    let repo = RegistrationRepository::new(pool);
    let seed = json!({"version":"1.0.0","entries":[
        {"name":"first","kind":"tool","upstream":"https://example.com","auth":{"kind":"none"}},
        {"name":"second","kind":"tool","upstream":"http://example.com","auth":{"kind":"none"},"protocol":"mcp_streamable_http","mcp":{"protocol_version":"2025-11-25"}}]});
    assert!(
        seed_loader::apply_catalog(&repo, &seed.to_string())
            .await
            .is_err()
    );
    assert!(repo.get("first").await.unwrap().is_none());
    assert!(repo.get_seed_version().await.unwrap().is_none());
}
