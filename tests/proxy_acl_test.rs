//! M9 — proxy hot path enforces per-agent bearer authentication and
//! per-tool ACL (`tool_allowlist` / `tool_denylist`).
//!
//! Companion to `audit_proxy_test.rs` (which exercises the M0/M1
//! shared-bearer path with no per-agent identity). These tests build
//! the agent router via `build_app_full(.., bearer_authenticator)` so
//! `auth_middleware` consults the BearerAuthenticator on every request
//! and `proxy_handler` enforces the agent's ACL before reaching upstream.

use agent_locksmith::app::build_app_full;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository, Decision, EventClass};
use agent_locksmith::secret::resolve_tool_creds_sync_env_only;
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Fixture {
    _dir: TempDir,
    audit: AuditRepository,
    agents: AgentRepository,
}

async fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool);
    Fixture {
        _dir: dir,
        audit,
        agents,
    }
}

fn yaml_for(upstream: &str) -> String {
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "things"
    description: "Things service"
    upstream: "{upstream}"
    timeouts:
      request_seconds: 5
      idle_seconds: 5
"#
    )
}

fn build_test_server(
    yaml: &str,
    audit: AuditRepository,
    bearer_authenticator: Arc<dyn AgentAuthenticator>,
) -> TestServer {
    let config = parse_config_str(yaml).unwrap();
    let resolved = resolve_tool_creds_sync_env_only(&config);
    let shared = Arc::new(ArcSwap::from_pointee(config));
    let app = build_app_full(
        shared,
        Some(audit),
        Arc::new(ArcSwap::from_pointee(resolved)),
        None, // mtls_authenticator
        Some(bearer_authenticator),
    );
    TestServer::new(app)
}

// TS-1: Valid lk_ token + tool in allowlist → 200, audit row carries
// agent_public_id and event=proxy_request. AC-3, AC-5.
#[tokio::test]
async fn ts1_valid_token_in_allowlist_returns_200_with_audit_identity() {
    let fx = fixture().await;
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/things/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let (pid, secret) = fx
        .agents
        .create(
            "agent-allow",
            None,
            Some(&["things".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(fx.agents.clone(), Some(fx.audit.clone())).unwrap(),
    );
    let server = build_test_server(&yaml_for(&mock.uri()), fx.audit.clone(), bearer);

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header(
            "Authorization",
            format!("Bearer lk_{pid}.{}", secret.expose_secret()),
        )
        .await;
    resp.assert_status_ok();

    let rows = fx
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .expect("query ok");
    let proxy_rows: Vec<_> = rows
        .iter()
        .filter(|r| r.event == "proxy_request" && r.event_class == EventClass::Proxy)
        .collect();
    assert_eq!(
        proxy_rows.len(),
        1,
        "expected exactly one proxy_request audit row"
    );
    let row = proxy_rows[0];
    assert_eq!(row.decision, Decision::Allowed);
    assert_eq!(row.status, Some(200));
    assert_eq!(row.tool.as_deref(), Some("things"));
    assert_eq!(
        row.agent_public_id.as_deref(),
        Some(pid.as_str()),
        "M9 wires per-agent identity into the proxy hot path"
    );
    assert_eq!(row.auth_method.as_deref(), Some("bearer"));
}
