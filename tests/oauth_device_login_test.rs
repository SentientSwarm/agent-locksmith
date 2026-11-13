//! #138 — operator device login for ChatGPT-plan (Codex) sessions,
//! against a mock of OpenAI's device-auth dialect.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::auth_v2::{BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::oauth::OauthAdminState;
use agent_locksmith::oauth::refresh::RefreshLockMap;
use agent_locksmith::oauth::sealing::SealingKey;
use agent_locksmith::oauth::session::OauthSessionRepository;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::{AgentRepository, BootstrapTokenRepository};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Harness {
    _dir: TempDir,
    server: TestServer,
    op_token: String,
    mock: MockServer,
    sessions: OauthSessionRepository,
    key: SealingKey,
    registrations: Arc<RegistrationRepository>,
    catalog: Arc<ArcSwap<Catalog>>,
    pool: sqlx::SqlitePool,
}

async fn setup() -> Harness {
    let dir = TempDir::new().unwrap();

    // Mint a real operator credential the same way admin_uds_test does.
    let op = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_token_wire = op.wire_format();
    let token_hash =
        argon2_helper::hash(&secrecy::SecretString::from(op.secret.expose().to_string())).unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op.public_id.as_str(),
            token_hash
        ),
    )
    .unwrap();

    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let sessions = OauthSessionRepository::new(pool.clone());
    let pool_for_harness = pool.clone();
    let sealing_key = SealingKey::generate().unwrap();

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    // Pre-register an OAuth-shaped registration. Mock token endpoint
    // URL is filled in below.
    let mock = MockServer::start().await;
    let token_url = format!("{}/oauth/token", mock.uri());

    let r = Registration::new(
        "codex".to_string(),
        Kind::Model,
        "Test OAuth registration".to_string(),
        "https://api.openai.example.com".to_string(),
        AuthSpec::OauthDeviceCode {
            client_id: "test-client".to_string(),
            scopes: vec!["openai-api".to_string()],
            device_url: format!("{}/api/accounts/deviceauth/usercode", mock.uri()),
            token_url: token_url.clone(),
            session_label: None,
        },
    );
    registrations.create(&r).await.unwrap();
    let other = Registration::new(
        "other".to_string(),
        Kind::Model,
        "Standard device-code provider".to_string(),
        "https://api.example.com".to_string(),
        AuthSpec::OauthDeviceCode {
            client_id: "c".to_string(),
            scopes: vec![],
            device_url: format!("{}/device", mock.uri()),
            token_url: format!("{}/token", mock.uri()),
            session_label: None,
        },
    );
    registrations.create(&other).await.unwrap();

    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));

    let admin = AdminService::new(agents.clone(), bootstrap, cfg_arc);
    let agent_auth = Arc::new(BearerAuthenticator::new(agents).unwrap());
    let operator_auth = Arc::new(OperatorAuthenticator::load(&ops_path).unwrap());

    let state = UdsState {
        broker_health: Default::default(),
        admin: Arc::new(admin),
        agent_auth,
        operator_auth,
        operator_mtls: None,
        registrations: Some(registrations.clone()),
        catalog: Some(catalog_arc.clone()),
        resolved_creds: None,
        oauth: Some(OauthAdminState {
            consent: None,
            registrations: registrations.clone(),
            sessions: sessions.clone(),
            sealing_key: sealing_key.clone(),
            catalog: catalog_arc.clone(),
            locks: RefreshLockMap::new(),
            device_logins: Default::default(),
        }),
        agent_creds: None,
        credential_sealing_key: None,
        credential_secrets: None,
        operational_log: None,
        operational_log_store: None,
        op_resolver: None,
    };
    let router = build_router(state);
    let server = TestServer::new(router);

    Harness {
        _dir: dir,
        server,
        op_token: op_token_wire,
        mock,
        sessions,
        key: sealing_key,
        registrations,
        catalog: catalog_arc,
        pool: pool_for_harness,
    }
}

const SECRETS: [&str; 4] = ["device-1", "auth-code", "verifier", "refresh-"];

fn auth(h: &Harness) -> String {
    format!("Bearer {}", h.op_token)
}

async fn mock_user_code(h: &Harness) {
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/usercode"))
        .and(body_string_contains("test-client"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_auth_id": "device-1",
            "user_code": "ABCD-EFGH",
            "interval": "1",
        })))
        .mount(&h.mock)
        .await;
}

/// First poll pends; the second returns the authorization code.
async fn mock_approval(h: &Harness) {
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/token"))
        .respond_with(ResponseTemplate::new(403))
        .up_to_n_times(1)
        .mount(&h.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/token"))
        .and(body_string_contains("device-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "authorization_code": "auth-code",
            "code_challenge": "challenge",
            "code_verifier": "verifier",
        })))
        .mount(&h.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code_verifier=verifier"))
        .and(body_string_contains("deviceauth%2Fcallback"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id_token": "id",
            "access_token": "access-login",
            "refresh_token": "refresh-login",
        })))
        .mount(&h.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh-login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-new",
            "refresh_token": "refresh-new",
            "expires_in": 3600,
        })))
        .mount(&h.mock)
        .await;
}

async fn start(h: &Harness, query: &str, body: serde_json::Value) -> axum_test::TestResponse {
    h.server
        .post(&format!("/admin/operator/oauth/codex/device-login{query}"))
        .add_header("authorization", auth(h))
        .json(&body)
        .await
}

async fn poll(h: &Harness, attempt: &str) -> axum_test::TestResponse {
    h.server
        .get(&format!(
            "/admin/operator/oauth/codex/device-login/{attempt}"
        ))
        .add_header("authorization", auth(h))
        .await
}

fn assert_no_secrets(text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "response leaked {s}: {text}");
    }
}

#[tokio::test]
async fn device_login_creates_a_session_without_exposing_tokens() {
    let h = setup().await;
    mock_user_code(&h).await;
    mock_approval(&h).await;

    let started = start(&h, "?label=acct3", serde_json::json!({})).await;
    started.assert_status(axum::http::StatusCode::ACCEPTED);
    assert_no_secrets(&started.text());
    let s: serde_json::Value = started.json();
    assert_eq!(s["user_code"], "ABCD-EFGH");
    assert_eq!(s["session_label"], "acct3");
    assert_eq!(s["interval"], 1);
    assert_eq!(
        s["verification_url"],
        format!("{}/codex/device", h.mock.uri())
    );
    let attempt = s["attempt"].as_str().unwrap().to_string();

    let first = poll(&h, &attempt).await;
    first.assert_status_ok();
    assert_eq!(first.json::<serde_json::Value>()["status"], "pending");

    let done = poll(&h, &attempt).await;
    done.assert_status_ok();
    assert_no_secrets(&done.text());
    let d: serde_json::Value = done.json();
    assert_eq!(d["status"], "complete");
    assert_eq!(d["session"]["session_label"], "acct3");
    assert_eq!(d["session"]["present"], true);
    assert_eq!(d["session"]["reconnect_required"], false);

    let session = h
        .sessions
        .get(&h.key, "codex", "acct3")
        .await
        .unwrap()
        .unwrap();
    assert!(!session.degraded);
    poll(&h, &attempt).await.assert_status_not_found();
}

#[tokio::test]
async fn healthy_session_needs_replace_but_degraded_one_does_not() {
    let h = setup().await;
    mock_user_code(&h).await;
    let healthy = h
        .sessions
        .create(&h.key, "codex", "default", "old", None, None, "")
        .await
        .unwrap();

    let refused = start(&h, "", serde_json::json!({})).await;
    refused.assert_status(axum::http::StatusCode::CONFLICT);
    assert_eq!(
        refused.json::<serde_json::Value>()["error"]["code"],
        "session_exists"
    );
    mock_approval(&h).await;
    let s: serde_json::Value = start(&h, "", serde_json::json!({"replace": true}))
        .await
        .json();
    let attempt = s["attempt"].as_str().unwrap();
    poll(&h, attempt).await.assert_status_ok();
    let d: serde_json::Value = poll(&h, attempt).await.json();
    assert_eq!(d["status"], "complete", "{d}");
    let replaced = h
        .sessions
        .get(&h.key, "codex", "default")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        replaced.incarnation, healthy.incarnation,
        "replace signs in again"
    );

    h.sessions.mark_degraded(&replaced).await.unwrap();
    h.mock.reset().await;
    mock_user_code(&h).await;
    mock_approval(&h).await;
    let s: serde_json::Value = start(&h, "", serde_json::json!({})).await.json();
    let attempt = s["attempt"].as_str().unwrap();
    poll(&h, attempt).await.assert_status_ok();
    let d: serde_json::Value = poll(&h, attempt).await.json();
    assert_eq!(d["status"], "complete", "{d}");
    let session = h
        .sessions
        .get(&h.key, "codex", "default")
        .await
        .unwrap()
        .unwrap();
    assert!(
        !session.degraded,
        "the degraded session was replaced in place"
    );
}

#[tokio::test]
async fn a_session_that_became_healthy_is_kept_without_exchanging_the_code() {
    let h = setup().await;
    mock_user_code(&h).await;
    mock_approval(&h).await;
    let s: serde_json::Value = start(&h, "", serde_json::json!({})).await.json();
    let attempt = s["attempt"].as_str().unwrap();
    poll(&h, attempt).await.assert_status_ok();
    // Someone bootstraps the label while the operator is signing in.
    h.sessions
        .create(&h.key, "codex", "default", "other", None, None, "")
        .await
        .unwrap();
    let late = poll(&h, attempt).await;
    late.assert_status(axum::http::StatusCode::CONFLICT);
    assert!(
        !code_exchanged(&h.mock.received_requests().await.unwrap()),
        "no grant is minted for a kept session"
    );
}

/// Start a login and see its first poll pend.
async fn pending_attempt(h: &Harness) -> String {
    mock_user_code(h).await;
    mock_approval(h).await;
    let s: serde_json::Value = start(h, "", serde_json::json!({})).await.json();
    let attempt = s["attempt"].as_str().unwrap().to_string();
    poll(h, &attempt).await.assert_status_ok();
    attempt
}

fn code_exchanged(requests: &[wiremock::Request]) -> bool {
    requests.iter().any(|r| {
        r.url.path() == "/oauth/token"
            && String::from_utf8_lossy(&r.body).contains("authorization_code")
    })
}

#[tokio::test]
async fn a_changed_issuer_never_receives_the_new_tokens() {
    let h = setup().await;
    let attempt = pending_attempt(&h).await;
    let elsewhere = MockServer::start().await;
    let mut r = h.registrations.get("codex").await.unwrap().unwrap();
    r.auth = AuthSpec::OauthDeviceCode {
        client_id: "test-client".to_string(),
        scopes: vec![],
        device_url: format!("{}/api/accounts/deviceauth/usercode", elsewhere.uri()),
        token_url: format!("{}/oauth/token", elsewhere.uri()),
        session_label: None,
    };
    h.registrations.upsert(&r).await.unwrap();
    h.catalog.store(Arc::new(
        Catalog::from_repo(h.registrations.as_ref()).await.unwrap(),
    ));

    let changed = poll(&h, &attempt).await;
    changed.assert_status(axum::http::StatusCode::CONFLICT);
    assert_eq!(
        changed.json::<serde_json::Value>()["error"]["code"],
        "authority_changed"
    );
    assert!(!code_exchanged(&h.mock.received_requests().await.unwrap()));
    assert!(elsewhere.received_requests().await.unwrap().is_empty());
    assert!(
        h.sessions
            .get(&h.key, "codex", "default")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_binding_that_pins_another_client_blocks_completion() {
    let h = setup().await;
    let attempt = pending_attempt(&h).await;
    let agents = agent_locksmith::repo::AgentRepository::new(h.pool.clone());
    agents
        .create("bound", None, None, None, None, None)
        .await
        .unwrap();
    let id = agents.get_by_name("bound").await.unwrap().unwrap().id;
    let pinned = AuthSpec::OauthDeviceCode {
        client_id: "pinned-client".to_string(),
        scopes: vec![],
        device_url: format!("{}/api/accounts/deviceauth/usercode", h.mock.uri()),
        token_url: format!("{}/oauth/token", h.mock.uri()),
        session_label: Some("default".to_string()),
    };
    agent_locksmith::repo::AgentCredentialRepository::new(h.pool.clone())
        .set(id, "codex", &pinned)
        .await
        .unwrap();
    let refused = poll(&h, &attempt).await;
    refused.assert_status(axum::http::StatusCode::CONFLICT);
    assert_eq!(
        refused.json::<serde_json::Value>()["error"]["code"],
        "authority_changed"
    );
    assert!(!code_exchanged(&h.mock.received_requests().await.unwrap()));
    assert!(
        h.sessions
            .get(&h.key, "codex", "default")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn publication_rolls_back_when_its_condition_fails_at_commit() {
    let h = setup().await;
    let refused = h
        .sessions
        .create_if(&h.key, "codex", "default", "refresh-x", || false)
        .await;
    assert!(matches!(
        refused,
        Err(agent_locksmith::oauth::OauthSessionError::Stale)
    ));
    assert!(
        h.sessions
            .get(&h.key, "codex", "default")
            .await
            .unwrap()
            .is_none()
    );
    let kept = h
        .sessions
        .create_if(&h.key, "codex", "default", "refresh-x", || true)
        .await
        .unwrap();
    assert_eq!(kept.session_label, "default");
}

#[tokio::test]
async fn revoke_ends_a_pending_login() {
    let h = setup().await;
    let attempt = pending_attempt(&h).await;
    h.server
        .delete("/admin/operator/oauth/codex")
        .add_header("authorization", auth(&h))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    poll(&h, &attempt).await.assert_status_not_found();
    assert!(!code_exchanged(&h.mock.received_requests().await.unwrap()));
    assert!(
        h.sessions
            .get(&h.key, "codex", "default")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_revoke_during_a_failing_first_refresh_leaves_nothing_behind() {
    let h = setup().await;
    mock_user_code(&h).await;
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "authorization_code": "auth-code",
            "code_challenge": "challenge",
            "code_verifier": "verifier",
        })))
        .mount(&h.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-login",
            "refresh_token": "refresh-login",
        })))
        .mount(&h.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(500).set_delay(std::time::Duration::from_millis(600)))
        .mount(&h.mock)
        .await;
    let s: serde_json::Value = start(&h, "", serde_json::json!({})).await.json();
    let attempt = s["attempt"].as_str().unwrap().to_string();
    let completing = poll(&h, &attempt);
    let revoking = async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        h.server
            .delete("/admin/operator/oauth/codex")
            .add_header("authorization", auth(&h))
            .await
    };
    let (done, revoke) = tokio::join!(completing, revoking);
    revoke.assert_status(axum::http::StatusCode::NO_CONTENT);
    done.assert_status(axum::http::StatusCode::CONFLICT);
    assert_eq!(
        done.json::<serde_json::Value>()["error"]["code"],
        "revoked_during_login"
    );
    assert!(
        h.sessions
            .get(&h.key, "codex", "default")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_failed_first_refresh_reports_why_and_can_be_retried() {
    let h = setup().await;
    mock_user_code(&h).await;
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "authorization_code": "auth-code",
            "code_challenge": "challenge",
            "code_verifier": "verifier",
        })))
        .mount(&h.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "refresh_token": "refresh-login",
        })))
        .mount(&h.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(400).set_body_string("refresh-leak"))
        .mount(&h.mock)
        .await;
    let s: serde_json::Value = start(&h, "", serde_json::json!({})).await.json();
    let failed = poll(&h, s["attempt"].as_str().unwrap()).await;
    failed.assert_status(axum::http::StatusCode::BAD_GATEWAY);
    assert_no_secrets(&failed.text());
    let e: serde_json::Value = failed.json();
    assert_eq!(e["error"]["code"], "device_login_failed");
    assert!(
        !e["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unreachable"),
        "{e}"
    );
    // Whatever the claim left behind needs reconnecting, so a rerun needs no --replace.
    if let Some(left) = h.sessions.get(&h.key, "codex", "default").await.unwrap() {
        assert!(left.degraded || left.refresh_pending);
        start(&h, "", serde_json::json!({}))
            .await
            .assert_status(axum::http::StatusCode::ACCEPTED);
    }
}

#[tokio::test]
async fn completion_warns_when_another_label_exists() {
    let h = setup().await;
    h.sessions
        .create(&h.key, "codex", "other-account", "x", None, None, "")
        .await
        .unwrap();
    let attempt = pending_attempt(&h).await;
    let d: serde_json::Value = poll(&h, &attempt).await.json();
    assert_eq!(d["status"], "complete", "{d}");
    assert!(
        d["warnings"].as_array().is_some_and(|w| !w.is_empty()),
        "{d}"
    );
}

#[tokio::test]
async fn other_dialects_and_unknown_attempts_are_refused() {
    let h = setup().await;
    let other = h
        .server
        .post("/admin/operator/oauth/other/device-login")
        .add_header("authorization", auth(&h))
        .json(&serde_json::json!({}))
        .await;
    other.assert_status_bad_request();
    assert_eq!(
        other.json::<serde_json::Value>()["error"]["code"],
        "device_login_unsupported"
    );
    poll(&h, "nope").await.assert_status_not_found();
    h.server
        .post("/admin/operator/oauth/codex/device-login")
        .json(&serde_json::json!({}))
        .await
        .assert_status_unauthorized();
}

#[tokio::test]
async fn provider_rejection_ends_the_attempt_without_echoing_its_body() {
    let h = setup().await;
    mock_user_code(&h).await;
    Mock::given(method("POST"))
        .and(path("/api/accounts/deviceauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_string("refresh-leak"))
        .mount(&h.mock)
        .await;
    let s: serde_json::Value = start(&h, "", serde_json::json!({})).await.json();
    let attempt = s["attempt"].as_str().unwrap();
    let failed = poll(&h, attempt).await;
    failed.assert_status(axum::http::StatusCode::BAD_GATEWAY);
    assert_no_secrets(&failed.text());
    assert_eq!(
        failed.json::<serde_json::Value>()["error"]["code"],
        "device_login_failed"
    );
    poll(&h, attempt).await.assert_status_not_found();
    assert!(
        h.sessions
            .get(&h.key, "codex", "default")
            .await
            .unwrap()
            .is_none()
    );
}
