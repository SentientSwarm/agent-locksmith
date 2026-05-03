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

/// Wire-format the (public_id, secret) pair as an `Authorization: Bearer
/// lk_<pid>.<secret>` header value.
fn bearer_header(pid: &str, secret: &secrecy::SecretString) -> String {
    format!("Bearer lk_{pid}.{}", secret.expose_secret())
}

/// Build a TestServer for `tools=[things]` with the given agent's
/// allowlist/denylist installed. Returns (server, fixture, bearer header).
async fn server_with_acl(
    fx: Fixture,
    upstream: &str,
    name: &str,
    allowlist: Option<Vec<String>>,
    denylist: Option<Vec<String>>,
) -> (TestServer, Fixture, String) {
    let allow = allowlist.as_deref();
    let deny = denylist.as_deref();
    let (pid, secret) = fx
        .agents
        .create(name, None, allow, deny, None, None)
        .await
        .unwrap();
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(fx.agents.clone(), Some(fx.audit.clone())).unwrap(),
    );
    let server = build_test_server(&yaml_for(upstream), fx.audit.clone(), bearer);
    let header = bearer_header(&pid, &secret);
    (server, fx, header)
}

/// Mount a 200-OK upstream at GET /v1/things/42 on the given mock.
async fn mount_things(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/things/42"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(mock)
        .await;
}

/// Convenience: filter audit rows down to the M9 ACL deny class.
async fn authz_denied_rows(audit: &AuditRepository) -> Vec<agent_locksmith::repo::audit::AuditEvent> {
    audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .expect("query ok")
        .into_iter()
        .filter(|r| r.event_class == EventClass::Security && r.event == "authz_denied")
        .collect()
}

// TS-1: Valid lk_ token + tool in allowlist → 200, audit row carries
// agent_public_id and event=proxy_request. AC-3, AC-5.
#[tokio::test]
async fn ts1_valid_token_in_allowlist_returns_200_with_audit_identity() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let (server, fx, header) =
        server_with_acl(fx, &mock.uri(), "agent-allow", Some(vec!["things".into()]), None).await;

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", header)
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
    assert!(row.agent_public_id.is_some(), "M9 stamps agent identity");
    assert_eq!(row.auth_method.as_deref(), Some("bearer"));
}

// TS-2: Valid lk_ token + tool NOT in allowlist → 403, audit row
// event_class=security event=authz_denied details.reason=not_in_allowlist.
// AC-4.
#[tokio::test]
async fn ts2_tool_not_in_allowlist_returns_403_authz_denied() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let (server, fx, header) = server_with_acl(
        fx,
        &mock.uri(),
        "agent-narrow",
        Some(vec!["other".into()]), // doesn't include "things"
        None,
    )
    .await;

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", header)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    let rows = authz_denied_rows(&fx.audit).await;
    assert_eq!(rows.len(), 1, "exactly one authz_denied row");
    let row = &rows[0];
    assert_eq!(row.decision, Decision::Denied);
    assert_eq!(row.status, Some(403));
    assert_eq!(row.tool.as_deref(), Some("things"));
    assert!(
        row.agent_public_id.is_some(),
        "agent identity recorded on deny too"
    );
    assert_eq!(
        row.details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str()),
        Some("not_in_allowlist"),
        "deny reason recorded in audit details"
    );
}

// TS-3: Valid lk_ token + tool IN denylist → 403, reason=in_denylist.
// AC-4.
#[tokio::test]
async fn ts3_tool_in_denylist_returns_403_authz_denied() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let (server, fx, header) = server_with_acl(
        fx,
        &mock.uri(),
        "agent-deny",
        None,
        Some(vec!["things".into()]),
    )
    .await;

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", header)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    let rows = authz_denied_rows(&fx.audit).await;
    assert_eq!(rows.len(), 1, "exactly one authz_denied row");
    let row = &rows[0];
    assert_eq!(
        row.details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str()),
        Some("in_denylist"),
    );
}

// TS-4: Valid lk_ token + neither list set → 200 (unrestricted). AC-3, AC-5.
#[tokio::test]
async fn ts4_no_acl_allows_request() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let (server, _fx, header) =
        server_with_acl(fx, &mock.uri(), "agent-open", None, None).await;

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", header)
        .await;
    resp.assert_status_ok();
}

// TS-5: Tool listed in BOTH allowlist and denylist → 403 (denylist wins).
// AC-4. Denial is always explicit; conflicting policy resolves to deny.
#[tokio::test]
async fn ts5_denylist_wins_over_allowlist() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let (server, fx, header) = server_with_acl(
        fx,
        &mock.uri(),
        "agent-conflict",
        Some(vec!["things".into()]),
        Some(vec!["things".into()]),
    )
    .await;

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", header)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    let rows = authz_denied_rows(&fx.audit).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str()),
        Some("in_denylist"),
        "denylist must win when both lists overlap"
    );
}
