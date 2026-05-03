//! M9 — proxy hot path enforces per-agent bearer authentication and
//! per-tool ACL (`tool_allowlist` / `tool_denylist`).
//!
//! Companion to `audit_proxy_test.rs` (which exercises the M0/M1
//! shared-bearer path with no per-agent identity). These tests build
//! the agent router via `build_app_full(.., agent_auth)` so
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
    agent_auth: Arc<dyn AgentAuthenticator>,
) -> TestServer {
    let config = parse_config_str(yaml).unwrap();
    let resolved = resolve_tool_creds_sync_env_only(&config);
    let shared = Arc::new(ArcSwap::from_pointee(config));
    let app = build_app_full(
        shared,
        Some(audit),
        Arc::new(ArcSwap::from_pointee(resolved)),
        None, // mtls_authenticator
        Some(agent_auth),
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
async fn authz_denied_rows(
    audit: &AuditRepository,
) -> Vec<agent_locksmith::repo::audit::AuditEvent> {
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
    let (server, fx, header) = server_with_acl(
        fx,
        &mock.uri(),
        "agent-allow",
        Some(vec!["things".into()]),
        None,
    )
    .await;

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
    let (server, _fx, header) = server_with_acl(fx, &mock.uri(), "agent-open", None, None).await;

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", header)
        .await;
    resp.assert_status_ok();
}

/// Pull all `auth_failure` security audit rows. BearerAuthenticator
/// emits these on every failed auth path; the wire response is the
/// same uniform 401 (per §4.7.9 / Q-8) but `details.reason` tells us
/// which path triggered.
async fn auth_failure_rows(
    audit: &AuditRepository,
) -> Vec<agent_locksmith::repo::audit::AuditEvent> {
    audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .expect("query ok")
        .into_iter()
        .filter(|r| r.event_class == EventClass::Security && r.event == "auth_failure")
        .collect()
}

fn assert_unauthorized_envelope(resp: &axum_test::TestResponse, expected_code: &str) {
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json();
    assert_eq!(
        body["error"]["type"].as_str(),
        Some("auth_error"),
        "body: {body}"
    );
    assert_eq!(
        body["error"]["code"].as_str(),
        Some(expected_code),
        "body: {body}"
    );
}

// TS-6: Missing Authorization header → 401, code=invalid_credential,
// audit reason=missing_credential. AC-3.
//
// The wire envelope keeps the uniform §4.7.9 shape per Q-8 (attackers
// can't distinguish "no header" from "wrong creds"), but the security
// audit captures the distinction so operators can detect probe traffic.
#[tokio::test]
async fn ts6_missing_authorization_returns_401_and_audits() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(fx.agents.clone(), Some(fx.audit.clone())).unwrap(),
    );
    let server = build_test_server(&yaml_for(&mock.uri()), fx.audit.clone(), bearer);

    let resp = server.get("/api/things/v1/things/42").await;
    assert_unauthorized_envelope(&resp, "invalid_credential");

    let rows = auth_failure_rows(&fx.audit).await;
    assert!(
        rows.iter().any(|r| r
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str())
            == Some("missing_credential")),
        "expected an auth_failure row with reason=missing_credential; got {rows:?}"
    );
}

// TS-6b: Authorization header present but contains non-ASCII bytes (or any
// otherwise-unparseable scheme) → 401 + audit reason=missing_credential.
// Falls under "missing or unparseable header" in §4.7.9 — same wire and
// audit shape as TS-6 so a probe with a junk header is just as visible.
#[tokio::test]
async fn ts6b_non_ascii_authorization_returns_401_and_audits() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(fx.agents.clone(), Some(fx.audit.clone())).unwrap(),
    );
    let server = build_test_server(&yaml_for(&mock.uri()), fx.audit.clone(), bearer);

    // axum_test forbids non-ASCII in `add_header`; use a non-Bearer scheme
    // instead — same `to_str().ok().strip_prefix("Bearer ")` failure path.
    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", "Basic dXNlcjpwYXNz")
        .await;
    assert_unauthorized_envelope(&resp, "invalid_credential");

    let rows = auth_failure_rows(&fx.audit).await;
    assert!(
        rows.iter().any(|r| r
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str())
            == Some("missing_credential")),
        "non-Bearer scheme must audit as missing_credential; got {rows:?}"
    );
}

// TS-7: Operator-namespace token (lkop_…) on the agent listener → 401,
// audit reason=wrong_namespace. AC-3.
#[tokio::test]
async fn ts7_operator_namespace_token_rejected() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(fx.agents.clone(), Some(fx.audit.clone())).unwrap(),
    );
    let server = build_test_server(&yaml_for(&mock.uri()), fx.audit.clone(), bearer);

    let op_token = agent_locksmith::token::StructuredToken::generate(
        agent_locksmith::token::TokenNamespace::Operator,
    );
    let resp = server
        .get("/api/things/v1/things/42")
        .add_header(
            "Authorization",
            format!("Bearer {}", op_token.wire_format()),
        )
        .await;
    assert_unauthorized_envelope(&resp, "invalid_credential");

    let rows = auth_failure_rows(&fx.audit).await;
    assert!(
        rows.iter().any(|r| r
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str())
            == Some("wrong_namespace")),
        "expected an auth_failure row with reason=wrong_namespace; got {rows:?}"
    );
}

// TS-8: Malformed token (no `.` separator) → 401, audit reason=malformed_token. AC-3.
#[tokio::test]
async fn ts8_malformed_token_rejected() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(fx.agents.clone(), Some(fx.audit.clone())).unwrap(),
    );
    let server = build_test_server(&yaml_for(&mock.uri()), fx.audit.clone(), bearer);

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", "Bearer lk_no_dot_separator")
        .await;
    assert_unauthorized_envelope(&resp, "invalid_credential");

    let rows = auth_failure_rows(&fx.audit).await;
    assert!(
        rows.iter().any(|r| r
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str())
            == Some("malformed_token")),
        "expected reason=malformed_token; got {rows:?}"
    );
}

// TS-9: Unknown public_id (well-formed token, never stored) → 401,
// audit reason=unknown_public_id. AC-3. The decoy-verify path in
// BearerAuthenticator keeps timing similar to TS-10; verifying that
// closure quantitatively belongs to auth_v2_test (unit), not here.
#[tokio::test]
async fn ts9_unknown_public_id_rejected() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(fx.agents.clone(), Some(fx.audit.clone())).unwrap(),
    );
    let server = build_test_server(&yaml_for(&mock.uri()), fx.audit.clone(), bearer);

    let bogus = agent_locksmith::token::StructuredToken::generate(
        agent_locksmith::token::TokenNamespace::Agent,
    );
    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", format!("Bearer {}", bogus.wire_format()))
        .await;
    assert_unauthorized_envelope(&resp, "invalid_credential");

    let rows = auth_failure_rows(&fx.audit).await;
    assert!(
        rows.iter().any(|r| r
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str())
            == Some("unknown_public_id")),
        "expected reason=unknown_public_id; got {rows:?}"
    );
}

// TS-10: Wrong secret on a known public_id → 401, audit reason=secret_mismatch. AC-3.
#[tokio::test]
async fn ts10_wrong_secret_rejected() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    // Mint an agent so the public_id exists; then craft a token that
    // reuses the public_id but a different secret.
    let (pid, _real_secret) = fx
        .agents
        .create("agent-mismatched", None, None, None, None, None)
        .await
        .unwrap();
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(fx.agents.clone(), Some(fx.audit.clone())).unwrap(),
    );
    let server = build_test_server(&yaml_for(&mock.uri()), fx.audit.clone(), bearer);
    let bogus_secret = agent_locksmith::token::StructuredToken::generate(
        agent_locksmith::token::TokenNamespace::Agent,
    );
    let resp = server
        .get("/api/things/v1/things/42")
        .add_header(
            "Authorization",
            format!("Bearer lk_{pid}.{}", bogus_secret.secret.expose()),
        )
        .await;
    assert_unauthorized_envelope(&resp, "invalid_credential");

    let rows = auth_failure_rows(&fx.audit).await;
    assert!(
        rows.iter().any(|r| r
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str())
            == Some("secret_mismatch")),
        "expected reason=secret_mismatch; got {rows:?}"
    );
}

// TS-11: Expired agent record → 401 even with the correct secret,
// audit reason=expired. AC-3. AuthError::Expired maps code=expired.
#[tokio::test]
async fn ts11_expired_agent_rejected() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;
    let fx = fixture().await;
    // Insert with expires_at in the past.
    let past_unix_secs = 1_000_000_000_i64; // 2001 — definitely expired
    let (pid, secret) = fx
        .agents
        .create(
            "agent-expired",
            None,
            None,
            None,
            None,
            Some(past_unix_secs),
        )
        .await
        .unwrap();
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(fx.agents.clone(), Some(fx.audit.clone())).unwrap(),
    );
    let server = build_test_server(&yaml_for(&mock.uri()), fx.audit.clone(), bearer);

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", bearer_header(&pid, &secret))
        .await;
    assert_unauthorized_envelope(&resp, "expired");

    let rows = auth_failure_rows(&fx.audit).await;
    assert!(
        rows.iter().any(|r| r
            .details
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str())
            == Some("expired")),
        "expected reason=expired; got {rows:?}"
    );
}

// TS-12: M0/M1 deployment regression. When `agent_auth` is
// None (no admin substrate), the legacy `inbound_auth.token` shared
// bearer path stays in force unchanged. AC-1.
#[tokio::test]
async fn ts12_m0_inbound_auth_token_path_still_works_without_agent_auth() {
    let mock = MockServer::start().await;
    mount_things(&mock).await;

    // M0-shape config: no admin_socket, no database. inbound_auth.token
    // is the only credential gate.
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
inbound_auth:
  mode: "bearer"
  token: "shared-secret-m0"
tools:
  - name: "things"
    description: "Things service"
    upstream: "{}"
    timeouts:
      request_seconds: 5
      idle_seconds: 5
"#,
        mock.uri()
    );
    let config = parse_config_str(&yaml).unwrap();
    let resolved = resolve_tool_creds_sync_env_only(&config);
    let shared = Arc::new(ArcSwap::from_pointee(config));
    // Build the router with agent_auth=None — the M9 branch
    // stays dormant and the M0 fallback handles the request.
    let app = build_app_full(
        shared,
        None,
        Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        None,
    );
    let server = TestServer::new(app);

    let resp = server
        .get("/api/things/v1/things/42")
        .add_header("Authorization", "Bearer shared-secret-m0")
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
