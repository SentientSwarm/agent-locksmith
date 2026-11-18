//! Phase F.6 — OAuth proxy hot-path integration tests with mock
//! provider. End-to-end exercise: register OAuth catalog entry →
//! bootstrap session → proxy call hits the mock upstream with
//! `Authorization: Bearer <access>` injected → audit row carries
//! `auth_mode: oauth_device_code` + `oauth_session_id`.
//!
//! TS-220..TS-225.

#[path = "support/bindings.rs"]
mod bindings;

use agent_locksmith::app::{OauthRuntime, build_app_full_with_phase_g};
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
    pool: sqlx::SqlitePool,
    bindings: agent_locksmith::repo::AgentCredentialRepository,
    catalog: Arc<ArcSwap<Catalog>>,
    registrations: Arc<RegistrationRepository>,
    oplog: agent_locksmith::repo::OperationalLogStore,
}

async fn setup() -> Harness {
    setup_with(false, None).await
}

/// `proxied`: make `codex` a proxied route, with token clients built from
/// the config as the daemon builds them; `egress_proxy` is that config's.
async fn setup_with(proxied: bool, egress_proxy: Option<&str>) -> Harness {
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

    let mut r = Registration::new(
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
    if proxied {
        r.egress = agent_locksmith::config::EgressMode::Proxied;
    }
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
    let account_bindings =
        bindings::select(&agents, &pool, &pid, &[("codex", r.auth.clone())]).await;
    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents, Some(audit.clone())).unwrap());
    let bearer_header = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    let proxy_line = egress_proxy.map_or(String::new(), |p| format!("egress_proxy: \"{p}\"\n"));
    let cfg = parse_config_str(&format!(
        "listen:\n  host: 127.0.0.1\n  port: 9200\n{proxy_line}"
    ))
    .unwrap();
    let token_clients = if proxied {
        agent_locksmith::client_pool::OauthClients::new(&cfg)
    } else {
        reqwest::Client::new().into()
    };
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    let runtime = OauthRuntime {
        sessions: sessions.clone(),
        sealing_key: sealing_key.clone(),
        locks: RefreshLockMap::new(),
        token_clients,
    };

    let oplog = agent_locksmith::repo::OperationalLogStore::new(pool.clone());
    let emitter = Arc::new(
        agent_locksmith::operational_log_sink::OperationalLogEmitter::spawn(oplog.clone(), 16),
    );
    let app = agent_locksmith::app::build_app_full_with_phase_k(
        cfg_arc,
        Some(audit.clone()),
        Arc::new(ArcSwap::from_pointee(Default::default())),
        None,
        Some(bearer),
        Some(registrations.clone()),
        catalog_arc.clone(),
        Some(runtime),
        Some(account_bindings.clone()),
        None,
        None,
        Some(emitter),
        None,
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
        pool,
        bindings: account_bindings,
        catalog: catalog_arc,
        registrations,
        oplog,
    }
}

/// Operational-log events written so far, waiting briefly for the drain.
async fn oplog_events(h: &Harness) -> Vec<agent_locksmith::repo::OperationalLogRecord> {
    let filter = agent_locksmith::repo::LogFilter {
        limit: 20,
        ..Default::default()
    };
    for _ in 0..100 {
        let rows = h.oplog.query(&filter).await.unwrap();
        if !rows.is_empty() {
            return rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Vec::new()
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
            &h.sessions
                .get(
                    &h.sealing_key,
                    "codex",
                    agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
                )
                .await
                .unwrap()
                .unwrap(),
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

// ─── TS-224: refresh failure retains pending custody + 503 ──────────────────
#[tokio::test]
async fn ts224_refresh_failure_requires_reconnect() {
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

    // Session is now pending; second call returns 503 without
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
    assert!(session.refresh_pending);
    assert!(!session.degraded);
    assert_eq!(
        resp2.json::<serde_json::Value>()["error"]["code"],
        "oauth_reconnect_required"
    );
    assert_eq!(h.mock.received_requests().await.unwrap().len(), 1);
}

/// AGENT-302 — a refresh made for a request fails after its claim like a
/// background one, and the operational log says the session needs
/// reconnecting.
#[tokio::test]
async fn an_inline_refresh_failure_is_logged() {
    let h = setup().await;
    seed_session(&h, "rt-bad", Some("at"), Some(unix_now() - 60)).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid_grant"))
        .mount(&h.mock)
        .await;
    h.server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await
        .assert_status_service_unavailable();
    let events = oplog_events(&h).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].event, "oauth_refresh_reconnect_required");
    let fields = events[0].fields.clone().unwrap();
    assert_eq!(fields["registration"], "codex");
    assert_eq!(fields["cause"], "revoked");
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

// ─── G2: chatgpt-account-id header injection on codex hot path ────────────

/// Build a fake JWT with the OpenAI `chatgpt_account_id` claim. Mirrors
/// the access-token shape codex's auth.openai.com mints.
fn jwt_with_chatgpt_account_id(account_id: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
                "chatgpt_plan_type": "pro",
            },
        })
        .to_string()
        .as_bytes(),
    );
    let sig = URL_SAFE_NO_PAD.encode(b"sig");
    format!("{header}.{payload}.{sig}")
}

/// Build a Harness with an upstream URL that mirrors the codex shape
/// (`<mock>/backend-api/codex`) so the inferred openai-codex-responses profile applies
/// against the wiremock host. Default Harness uses `mock.uri()` as a
/// bare host which doesn't match the codex pattern.
async fn setup_codex_shaped() -> Harness {
    setup_codex_shaped_with(None).await
}

/// Codex-shaped harness with an explicit route profile (brokered routes
/// phase 1). `None` keeps the profile inferred from the upstream.
async fn setup_codex_shaped_with(
    profile: Option<agent_locksmith::registrations::RouteProfile>,
) -> Harness {
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

    // Register with codex-shaped upstream so the matcher fires.
    let mut r = Registration::new(
        "codex".to_string(),
        Kind::Model,
        "OAuth test (codex-shaped)".to_string(),
        format!("{}/backend-api/codex", mock.uri()),
        AuthSpec::OauthDeviceCode {
            client_id: "test-client".to_string(),
            scopes: vec!["openai-api".to_string()],
            device_url: format!("{}/device", mock.uri()),
            token_url,
            session_label: None,
        },
    );
    r.profile = profile;
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
    let account_bindings =
        bindings::select(&agents, &pool, &pid, &[("codex", r.auth.clone())]).await;
    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents, Some(audit.clone())).unwrap());
    let bearer_header = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    let runtime = OauthRuntime {
        sessions: sessions.clone(),
        sealing_key: sealing_key.clone(),
        locks: RefreshLockMap::new(),
        token_clients: reqwest::Client::new().into(),
    };
    let pool_for_log = pool.clone();

    let app = build_app_full_with_phase_g(
        cfg_arc,
        Some(audit.clone()),
        Arc::new(ArcSwap::from_pointee(Default::default())),
        None,
        Some(bearer),
        Some(registrations.clone()),
        catalog_arc.clone(),
        Some(runtime),
        Some(account_bindings.clone()),
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
        pool,
        bindings: account_bindings,
        catalog: catalog_arc,
        registrations,
        oplog: agent_locksmith::repo::OperationalLogStore::new(pool_for_log),
    }
}

#[tokio::test]
async fn g2_proxy_injects_chatgpt_account_id_when_session_has_jwt_account_id() {
    let h = setup_codex_shaped().await;
    let access_token = jwt_with_chatgpt_account_id("acct_test_g2_inject");
    h.sessions
        .create(
            &h.sealing_key,
            "codex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
            "rt",
            Some(&access_token),
            Some(unix_now() + 3600),
            "",
        )
        .await
        .unwrap();

    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(header("chatgpt-account-id", "acct_test_g2_inject"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn g2_proxy_skips_account_id_header_when_session_has_no_jwt() {
    // Non-JWT access token — `account_id` stays None on the session
    // row, header should NOT be injected. wiremock matcher rejects
    // requests carrying chatgpt-account-id; if locksmith mistakenly
    // injects, the request 404s.
    let h = setup_codex_shaped().await;
    h.sessions
        .create(
            &h.sealing_key,
            "codex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
            "rt",
            Some("not-a-jwt-just-a-string"),
            Some(unix_now() + 3600),
            "",
        )
        .await
        .unwrap();

    use wiremock::matchers::header_exists;
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(header_exists("chatgpt-account-id"))
        .respond_with(ResponseTemplate::new(500).set_body_string("should not reach"))
        .mount(&h.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok-no-header"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "ok-no-header");
}

#[tokio::test]
async fn g2_proxy_skips_account_id_header_when_upstream_is_not_codex() {
    // Default Harness — upstream is `mock.uri()` (no `/backend-api/codex`
    // path). Even if the access token is a valid OpenAI JWT, the
    // header should not be injected — matcher fires on the upstream
    // pattern, not the JWT shape.
    let h = setup().await;
    let access_token = jwt_with_chatgpt_account_id("acct_should_not_inject");
    h.sessions
        .create(
            &h.sealing_key,
            "codex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
            "rt",
            Some(&access_token),
            Some(unix_now() + 3600),
            "",
        )
        .await
        .unwrap();

    use wiremock::matchers::header_exists;
    Mock::given(method("GET"))
        .and(path("/v1/whatever"))
        .and(header_exists("chatgpt-account-id"))
        .respond_with(ResponseTemplate::new(500).set_body_string("should not reach"))
        .mount(&h.mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/whatever"))
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

#[tokio::test]
async fn g2_proxy_skips_account_id_header_when_profile_is_generic_on_codex_upstream() {
    // Brokered routes phase 1: an explicit `generic` profile beats the
    // `/backend-api/codex` inference, so a session with a valid account_id
    // still sends no ChatGPT-Account-ID header.
    let h =
        setup_codex_shaped_with(Some(agent_locksmith::registrations::RouteProfile::Generic)).await;
    let access_token = jwt_with_chatgpt_account_id("acct_should_not_inject");
    h.sessions
        .create(
            &h.sealing_key,
            "codex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
            "rt",
            Some(&access_token),
            Some(unix_now() + 3600),
            "",
        )
        .await
        .unwrap();

    use wiremock::matchers::header_exists;
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(header_exists("chatgpt-account-id"))
        .respond_with(ResponseTemplate::new(500).set_body_string("should not reach"))
        .mount(&h.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok-no-header"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "ok-no-header");
}

#[path = "source_isolation/oauth.rs"]
mod isolation;

#[path = "account_bindings/logs.rs"]
mod logs;

/// AGENT-269 — a proxied route's inline refresh goes through the egress
/// proxy, as its API call does. The provider itself is never reached
/// directly: an HTTP proxy receives absolute-form requests, so only the
/// proxy can answer.
#[tokio::test]
async fn proxied_route_refreshes_through_the_egress_proxy() {
    let proxy = MockServer::start().await;
    let h = setup_with(true, Some(&proxy.uri())).await;
    seed_session(&h, "rt-old", Some("at-expired"), Some(unix_now() - 60)).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at-fresh",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&proxy)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/whatever"))
        .and(header("authorization", "Bearer at-fresh"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&proxy)
        .await;
    let resp = h
        .server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_ok();
    assert!(
        h.mock.received_requests().await.unwrap().is_empty(),
        "nothing may reach the provider without the proxy"
    );
}

/// AGENT-269 — with no egress configured, a proxied route's expired
/// session is not refreshed directly: the request fails closed, the
/// provider is never contacted, and the session is left usable for when
/// egress is configured.
#[tokio::test]
async fn proxied_route_without_egress_never_refreshes_directly() {
    let h = setup_with(true, None).await;
    seed_session(&h, "rt-old", Some("at-expired"), Some(unix_now() - 60)).await;
    let resp = h
        .server
        .get("/api/codex/v1/whatever")
        .add_header("authorization", &h.bearer_header)
        .await;
    resp.assert_status_service_unavailable();
    assert_eq!(
        resp.json::<serde_json::Value>()["error"]["code"],
        "egress_proxy_unconfigured"
    );
    assert!(h.mock.received_requests().await.unwrap().is_empty());
    // AGENT-302: audited as the refused route itself is, a security
    // `egress_unenforced` event, not an `oauth_unavailable` one.
    let events: Vec<(String, String)> =
        sqlx::query_as("SELECT event, event_class FROM audit WHERE status = 503")
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        events,
        vec![("egress_unenforced".to_string(), "security".to_string())]
    );
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
    assert!(!session.degraded && !session.refresh_pending);
}
