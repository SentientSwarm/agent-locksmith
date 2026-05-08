//! Phase E.6 — authless wire path. TS-150..TS-152.
//!
//! Verifies that `kind=tool` registrations with `auth: none`:
//! 1. Proxy without injecting an `Authorization` (or any other) auth
//!    header, even when the agent sends one (which is stripped).
//! 2. Record `auth_mode: "none"` in the proxy_request audit row.
//! 3. Still pass through the per-agent ACL gate — `auth: none` does
//!    not make a tool universally callable.

use agent_locksmith::app::build_app_full_with_catalog;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository};
use agent_locksmith::secret::resolve_tool_creds_sync_env_only;
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const YAML: &str = r#"
listen:
  host: "127.0.0.1"
  port: 9200
"#;

struct Harness {
    _dir: TempDir,
    server: TestServer,
    audit: AuditRepository,
    bearer_header: String,
}

/// Spawn an agent listener with a registrations-backed catalog and a
/// pre-registered agent. The agent's allowlist defaults to `None`
/// (allow-all); pass `Some(vec![...])` to restrict for the ACL test.
async fn setup(upstream: &str, auth: AuthSpec, tool_allowlist: Option<Vec<String>>) -> Harness {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool));

    // Seed the registration under test.
    let r = Registration::new(
        "public-search".to_string(),
        Kind::Tool,
        "Authless tool".to_string(),
        upstream.to_string(),
        auth,
    );
    registrations.create(&r).await.unwrap();

    let allow_ref = tool_allowlist.as_deref();
    let (pid, secret) = agents
        .create("authless-test", None, allow_ref, None, None, None)
        .await
        .unwrap();

    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents, Some(audit.clone())).unwrap());

    let cfg = parse_config_str(YAML).unwrap();
    let resolved = resolve_tool_creds_sync_env_only(&cfg);
    let shared = Arc::new(ArcSwap::from_pointee(cfg));

    // Phase E.6: build the catalog from the seeded registration so the
    // proxy hot path picks up the new path.
    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));

    let app = build_app_full_with_catalog(
        shared,
        Some(audit.clone()),
        Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        Some(bearer),
        Some(registrations),
        catalog_arc,
    );
    let server = TestServer::new(app);
    let bearer_header = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    Harness {
        _dir: dir,
        server,
        audit,
        bearer_header,
    }
}

// ─── TS-150: authless tool proxies without injecting any auth header ───────
#[tokio::test]
async fn ts150_authless_tool_proxies_without_header_injection() {
    let mock = MockServer::start().await;
    // The matcher requires zero `Authorization` / `x-api-key` headers
    // on the upstream request. If locksmith injected anything, no
    // mount matches and wiremock returns the default 404; the proxy
    // wraps that as a 404 to the agent. The 200 below proves the
    // forwarded request was credential-free.
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(NoAuthHeader)
        .respond_with(ResponseTemplate::new(200).set_body_string("hits"))
        .mount(&mock)
        .await;

    let h = setup(&mock.uri(), AuthSpec::None, None).await;

    let resp = h
        .server
        .get("/api/public-search/search")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
    resp.assert_text("hits");
}

// ─── TS-150b: authless tool strips an agent-supplied X-API-Key ──────────────
#[tokio::test]
async fn ts150b_authless_tool_strips_agent_supplied_x_api_key() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(NoAuthHeader)
        .respond_with(ResponseTemplate::new(200).set_body_string("hits"))
        .mount(&mock)
        .await;

    let h = setup(&mock.uri(), AuthSpec::None, None).await;

    // Defense in depth: even when the registration is `auth: none`,
    // an agent that injects its own `x-api-key` should not have it
    // reach the upstream — locksmith always strips auth-shaped
    // headers regardless of the registration's auth shape.
    let resp = h
        .server
        .get("/api/public-search/search")
        .add_header("authorization", &h.bearer_header)
        .add_header("x-api-key", "agent-supplied-key")
        .await;
    resp.assert_status_ok();
    resp.assert_text("hits");
}

// ─── TS-151: audit row records auth_mode: "none" for authless requests ─────
#[tokio::test]
async fn ts151_audit_records_auth_mode_none() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock)
        .await;

    let h = setup(&mock.uri(), AuthSpec::None, None).await;

    let resp = h
        .server
        .get("/api/public-search/search")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();

    let rows = h
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let proxy_row = rows
        .iter()
        .find(|r| r.event == "proxy_request")
        .expect("expected one proxy_request audit row");
    let details = proxy_row
        .details
        .as_ref()
        .expect("proxy_request audit row should carry details");
    assert_eq!(
        details.get("auth_mode").and_then(|v| v.as_str()),
        Some("none"),
        "expected auth_mode=none in details; got {details:?}"
    );
}

// ─── TS-152: authless tool still gates on agent ACL ─────────────────────────
#[tokio::test]
async fn ts152_authless_tool_still_gated_by_acl() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;

    // Agent's allowlist excludes the authless tool.
    let h = setup(
        &mock.uri(),
        AuthSpec::None,
        Some(vec!["something-else".to_string()]),
    )
    .await;

    let resp = h
        .server
        .get("/api/public-search/search")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_forbidden();
    let body: serde_json::Value = resp.json();
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("tool_not_allowed"),
        "expected tool_not_allowed; got {body}"
    );
}

// ─── helper matcher: assert the request did NOT carry an auth header ────────
struct NoAuthHeader;

impl wiremock::Match for NoAuthHeader {
    fn matches(&self, request: &wiremock::Request) -> bool {
        !request.headers.contains_key("authorization")
            && !request.headers.contains_key("Authorization")
            && !request.headers.contains_key("x-api-key")
            && !request.headers.contains_key("X-Api-Key")
    }
}
