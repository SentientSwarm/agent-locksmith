//! Phase F.6 — OAuth proxy hot-path integration tests with mock
//! provider. End-to-end exercise: register OAuth catalog entry →
//! bootstrap session → proxy call hits the mock upstream with
//! `Authorization: Bearer <access>` injected → audit row carries
//! `auth_mode: oauth_device_code` + `oauth_session_id`.
//!
//! TS-220..TS-225.

use agent_locksmith::app::{OauthRuntime, build_app_full_with_oauth};
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::oauth::refresh::RefreshLockMap;
use agent_locksmith::oauth::sealing::SealingKey;
use agent_locksmith::oauth::session::OauthSessionRepository;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Fully-wired OAuth test harness:
/// - Pre-registered OAuth `kind=model` registration (`codex`).
/// - Mock OAuth token endpoint at `<mock>/token`.
/// - Mock upstream API at `<mock>/v1/whatever`.
/// - Pre-registered agent `oauth-test` allowed to call `codex`.
struct Harness {
    _dir: TempDir,
    server: TestServer,
    bearer_header: String,
    audit: AuditRepository,
    sessions: OauthSessionRepository,
    sealing_key: SealingKey,
    mock: MockServer,
}

async fn setup() -> Harness {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let sessions = OauthSessionRepository::new(pool.clone());
    let sealing_key = SealingKey::generate().unwrap();

    let mock = MockServer::start().await;
    let token_url = format!("{}/token", mock.uri());

    let r = Registration::new(
        "codex".to_string(),
        Kind::Model,
        "OAuth test".to_string(),
        mock.uri(),
        AuthSpec::OauthDeviceCode {
            client_id: "test-client".to_string(),
            scopes: vec!["openai-api".to_string()],
            device_url: format!("{}/device", mock.uri()),
            token_url,
            session_label: None,
        },
    );
    registrations.create(&r).await.unwrap();

    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));

    let (pid, secret) = agents
        .create(
            "oauth-test",
            None,
            Some(&["codex".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents, Some(audit.clone())).unwrap());
    let bearer_header = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    let runtime = OauthRuntime {
        sessions: sessions.clone(),
        sealing_key: sealing_key.clone(),
        locks: RefreshLockMap::new(),
        refresh_client: reqwest::Client::new(),
    };

    let app = build_app_full_with_oauth(
        cfg_arc,
        Some(audit.clone()),
        Arc::new(ArcSwap::from_pointee(Default::default())),
        None,
        Some(bearer),
        Some(registrations),
        catalog_arc,
        Some(runtime),
    );
    let server = TestServer::new(app);

    Harness {
        _dir: dir,
        server,
        bearer_header,
        audit,
        sessions,
        sealing_key,
        mock,
    }
}

/// Helper: directly seed an OAuth session in the DB (simulates the
/// outcome of `locksmith oauth bootstrap`). Used by tests that want
/// to exercise the proxy hot path without re-running the bootstrap
/// admin endpoint.
async fn seed_session(h: &Harness, refresh: &str, access: Option<&str>, expires_at: Option<i64>) {
    h.sessions
        .create(
            &h.sealing_key,
            "codex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
            refresh,
            access,
            expires_at,
            "",
        )
        .await
        .unwrap();
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ─── TS-220: proxy injects access token from oauth_sessions cache ──────────
#[tokio::test]
async fn ts220_proxy_injects_access_token_from_cache() {
    let h = setup().await;
    seed_session(
        &h,
        "refresh-x",
        Some("access-cached"),
        Some(unix_now() + 3600),
    )
    .await;

    Mock::given(method("GET"))
        .and(path("/v1/whatever"))
        .and(header("authorization", "Bearer access-cached"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
}

// ─── TS-221: missing session → 503 oauth_session_missing ───────────────────
#[tokio::test]
async fn ts221_missing_session_returns_503() {
    let h = setup().await;
    let resp = h
        .server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_service_unavailable();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "oauth_session_missing");
}

// ─── TS-222: degraded session → 503 oauth_refresh_failed ───────────────────
#[tokio::test]
async fn ts222_degraded_session_returns_503() {
    let h = setup().await;
    seed_session(&h, "rt", Some("at"), Some(unix_now() + 3600)).await;
    h.sessions
        .mark_degraded(
            "codex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
        )
        .await
        .unwrap();

    let resp = h
        .server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_service_unavailable();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "oauth_refresh_failed");
}

// ─── TS-223: expired access token triggers inline refresh + retry ──────────
#[tokio::test]
async fn ts223_expired_access_token_triggers_inline_refresh() {
    let h = setup().await;
    // Access token already expired → should trigger refresh.
    seed_session(&h, "rt-old", Some("at-expired"), Some(unix_now() - 60)).await;

    // Mock the token endpoint to return a fresh access token.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at-fresh",
            "expires_in": 3600,
        })))
        .mount(&h.mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/whatever"))
        .and(header("authorization", "Bearer at-fresh"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
}

// ─── TS-224: refresh failure marks session degraded + 503 ──────────────────
#[tokio::test]
async fn ts224_refresh_failure_marks_session_degraded() {
    let h = setup().await;
    seed_session(&h, "rt-bad", Some("at"), Some(unix_now() - 60)).await;

    // Mock returns 401 invalid_grant → refresh fails.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid_grant"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_service_unavailable();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "oauth_refresh_failed");

    // Session is now degraded; second call returns 503 without
    // hitting the token endpoint again.
    let resp2 = h
        .server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp2.assert_status_service_unavailable();
    let session = h
        .sessions
        .get(
            &h.sealing_key,
            "codex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(session.degraded);
}

// ─── TS-225: audit row carries auth_mode + oauth_session_id ────────────────
#[tokio::test]
async fn ts225_audit_records_oauth_auth_mode_and_session_id() {
    let h = setup().await;
    seed_session(&h, "rt", Some("at"), Some(unix_now() + 3600)).await;
    Mock::given(method("GET"))
        .and(path("/v1/whatever"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&h.mock)
        .await;
    h.server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await
        .assert_status_ok();

    let rows = h
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let proxy_row = rows
        .iter()
        .find(|r| r.event == "proxy_request")
        .expect("expected one proxy_request audit row");
    let details = proxy_row.details.as_ref().unwrap();
    assert_eq!(details["auth_mode"], "oauth_device_code");
    let sid = details["oauth_session_id"].as_str().unwrap();
    assert_eq!(sid.len(), 16);
}
