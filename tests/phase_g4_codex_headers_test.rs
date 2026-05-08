//! Phase G4 — codex required headers (`OpenAI-Beta`, `originator`)
//! injection integration tests.
//!
//! End-to-end coverage: agent POSTs to a codex upstream without
//! `OpenAI-Beta` or `originator`; locksmith injects both. The
//! wiremock matcher asserts both headers are present on the
//! upstream request — if locksmith doesn't inject, mock returns 404
//! and the test fails.
//!
//! Mirrors the harness pattern from `tests/phase_g3_codex_body_test.rs`.

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
use agent_locksmith::repo::audit::AuditRepository;
use arc_swap::ArcSwap;
use axum_test::TestServer;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

/// Custom matcher: succeeds when the request does NOT carry the
/// named header. wiremock has no built-in negation; this is the
/// minimal local equivalent.
struct HeaderAbsent(&'static str);
impl Match for HeaderAbsent {
    fn matches(&self, req: &Request) -> bool {
        !req.headers.contains_key(self.0)
    }
}

struct Harness {
    _dir: TempDir,
    server: TestServer,
    bearer_header: String,
    mock: MockServer,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn jwt_with_account_id(account_id: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
            },
        })
        .to_string()
        .as_bytes(),
    );
    let sig = URL_SAFE_NO_PAD.encode(b"sig");
    format!("{header}.{payload}.{sig}")
}

/// Spin up a Harness with two registrations:
/// - `codex` — codex-shaped upstream (`<mock>/backend-api/codex`).
/// - `noncodex` — non-codex upstream (`<mock>/v1`), used to verify
///   G4 injection is gated.
///
/// Agent name is `g4-test-agent` so we can verify the originator
/// fallback uses it.
async fn setup(agent_name: &str) -> Harness {
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

    let codex_reg = Registration::new(
        "codex".to_string(),
        Kind::Model,
        "G4 codex test".to_string(),
        format!("{}/backend-api/codex", mock.uri()),
        AuthSpec::OauthDeviceCode {
            client_id: "test-client".to_string(),
            scopes: vec!["openai-api".to_string()],
            device_url: format!("{}/device", mock.uri()),
            token_url: token_url.clone(),
            session_label: None,
        },
    );
    registrations.create(&codex_reg).await.unwrap();

    let noncodex_reg = Registration::new(
        "noncodex".to_string(),
        Kind::Model,
        "G4 non-codex control".to_string(),
        format!("{}/v1", mock.uri()),
        AuthSpec::OauthDeviceCode {
            client_id: "test-client".to_string(),
            scopes: vec!["openai-api".to_string()],
            device_url: format!("{}/device", mock.uri()),
            token_url,
            session_label: None,
        },
    );
    registrations.create(&noncodex_reg).await.unwrap();

    let access_token = jwt_with_account_id("acct_g4_test");
    sessions
        .create(
            &sealing_key,
            "codex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
            "rt-codex",
            Some(&access_token),
            Some(unix_now() + 3600),
            "",
        )
        .await
        .unwrap();
    sessions
        .create(
            &sealing_key,
            "noncodex",
            agent_locksmith::oauth::session::DEFAULT_SESSION_LABEL,
            "rt-noncodex",
            Some(&access_token),
            Some(unix_now() + 3600),
            "",
        )
        .await
        .unwrap();

    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));

    let (pid, secret) = agents
        .create(
            agent_name,
            None,
            Some(&["codex".to_string(), "noncodex".to_string()]),
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
        sessions,
        sealing_key,
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
        mock,
    }
}

#[tokio::test]
async fn g4_proxy_injects_openai_beta_and_originator_when_agent_omits_them() {
    let h = setup("hermes-mini-1").await;

    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(header("openai-beta", "responses=experimental"))
        .and(header("originator", "hermes-mini-1"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .json(&json!({
            "model": "gpt-5.5",
            "input": [{"type": "message", "role": "user", "content": "hi"}],
        }))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn g4_proxy_overrides_agent_supplied_openai_beta() {
    // Agent sends a wrong OpenAI-Beta value (e.g., copy-pasted from
    // some other endpoint); locksmith strips and forces the codex
    // value. wiremock matcher fails if a wrong/duplicated value
    // reaches upstream.
    let h = setup("openclaw-mini-1").await;

    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(header("openai-beta", "responses=experimental"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .add_header("openai-beta", "wrong=value")
        .json(&json!({
            "model": "gpt-5.5",
            "input": [{"type": "message", "role": "user", "content": "hi"}],
        }))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn g4_proxy_preserves_agent_supplied_originator() {
    let h = setup("openclaw-mini-1").await;

    Mock::given(method("POST"))
        .and(path("/backend-api/codex/responses"))
        .and(header("openai-beta", "responses=experimental"))
        .and(header("originator", "codex_cli_rs"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/responses")
        .add_header("authorization", &h.bearer_header)
        .add_header("originator", "codex_cli_rs")
        .json(&json!({
            "model": "gpt-5.5",
            "input": [{"type": "message", "role": "user", "content": "hi"}],
        }))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn g4_proxy_skips_g4_headers_for_non_codex_upstream() {
    let h = setup("hermes-mini-1").await;

    // Non-codex upstream — neither OpenAI-Beta nor originator
    // should be injected. Mock matcher rejects requests carrying
    // either header.
    Mock::given(method("POST"))
        .and(path("/v1/anything"))
        .and(HeaderAbsent("openai-beta"))
        .and(HeaderAbsent("originator"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/noncodex/anything")
        .add_header("authorization", &h.bearer_header)
        .json(&json!({"any": "body"}))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn g4_proxy_injects_g4_headers_on_non_responses_codex_paths() {
    // G4 fires on every codex upstream call, not just /responses.
    // (Compare to G3, which is /responses-only.) A hypothetical
    // /backend-api/codex/sessions call also gets the G4 headers.
    let h = setup("hermes-mini-1").await;

    Mock::given(method("POST"))
        .and(path("/backend-api/codex/sessions"))
        .and(header("openai-beta", "responses=experimental"))
        .and(header("originator", "hermes-mini-1"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .post("/api/codex/sessions")
        .add_header("authorization", &h.bearer_header)
        .json(&json!({"any": "body"}))
        .await;
    resp.assert_status_ok();
}
