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
        admin: Arc::new(admin),
        agent_auth,
        operator_auth,
        operator_mtls: None,
        registrations: Some(registrations.clone()),
        catalog: Some(catalog_arc.clone()),
        resolved_creds: None,
        oauth: Some(OauthAdminState {
            consent: None,
            registrations,
            sessions: sessions.clone(),
            sealing_key: sealing_key.clone(),
            catalog: catalog_arc,
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
        .expect(1)
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
    start(&h, "", serde_json::json!({"replace": true}))
        .await
        .assert_status(axum::http::StatusCode::ACCEPTED);

    h.sessions.mark_degraded(&healthy).await.unwrap();
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
