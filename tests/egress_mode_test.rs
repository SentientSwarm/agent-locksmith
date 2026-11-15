//! AGENT-259 / AGENT-261 — egress enforcement is an explicit decision.
//!
//! A `proxied` route never goes direct because a proxy is missing: with no
//! `egress_proxy` and no `egress.mode` it fails closed. `egress.mode:
//! external` declares that the surrounding infrastructure enforces egress,
//! and `pipelock` (the default whenever `egress_proxy` is set) sends every
//! proxied route through the proxy.

use agent_locksmith::app::build_app_full_with_phase_j;
use agent_locksmith::auth_v2::BearerAuthenticator;
use agent_locksmith::config::{AppConfig, EgressEnforcement, EgressMode, parse_config_str};
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::audit::AuditRepository;
use agent_locksmith::repo::{AgentCredentialRepository, AgentRepository};
use agent_locksmith::secret::resolve_tool_creds_sync_env_only;
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

struct H {
    server: TestServer,
    pool: sqlx::SqlitePool,
    _dir: TempDir,
}

fn yaml(upstream: &str, extra: &str) -> String {
    format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
{extra}
tools:
  - name: "out"
    description: "Internet route"
    upstream: "{upstream}"
    egress: proxied
"#
    )
}

async fn harness(config: AppConfig) -> H {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("egress.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let (pid, token) = agents
        .create("agent", None, None, None, None, None)
        .await
        .unwrap();
    let id = agents
        .get_active_by_public_id(&pid)
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut route = Registration::new(
        "out".into(),
        Kind::Tool,
        "Internet route".into(),
        config.tools[0].upstream.clone(),
        AuthSpec::None,
    );
    route.egress = EgressMode::Proxied;
    RegistrationRepository::new(pool.clone())
        .create(&route)
        .await
        .unwrap();
    let selections = AgentCredentialRepository::new(pool.clone());
    selections.set(id, "out", &AuthSpec::None).await.unwrap();
    agents
        .update_policy(&pid, Some(Some(vec!["out".into()])), None, None, None)
        .await
        .unwrap();
    let audit = AuditRepository::new(pool.clone());
    let resolved = resolve_tool_creds_sync_env_only(&config);
    let app = build_app_full_with_phase_j(
        Arc::new(ArcSwap::from_pointee(config)),
        Some(audit.clone()),
        Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        Some(Arc::new(
            BearerAuthenticator::with_audit(agents, Some(audit)).unwrap(),
        )),
        None,
        Arc::new(ArcSwap::from_pointee(Catalog::default())),
        None,
        Some(selections),
        None,
        None,
    );
    let mut server = TestServer::new(app);
    server.add_header(
        "authorization",
        &format!("Bearer lk_{pid}.{}", token.expose_secret()),
    );
    H {
        server,
        pool,
        _dir: dir,
    }
}

async fn upstream_ok() -> MockServer {
    let m = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&m)
        .await;
    m
}

#[test]
fn pipelock_mode_requires_egress_proxy() {
    let err = parse_config_str(&yaml("https://up.example", "egress:\n  mode: pipelock"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("egress_proxy"), "{err}");
}

#[test]
fn invalid_egress_proxy_is_rejected() {
    let err = parse_config_str(&yaml("https://up.example", "egress_proxy: \"not a url\""))
        .unwrap_err()
        .to_string();
    assert!(err.contains("egress_proxy"), "{err}");
}

#[test]
fn invalid_proxy_error_never_echoes_the_url() {
    // A proxy URL can carry credentials; a config error must not print it.
    let err = parse_config_str(&yaml(
        "https://up.example",
        "egress_proxy: \"http://user:s3cret-pw@[bad\"",
    ))
    .unwrap_err()
    .to_string();
    assert!(!err.contains("s3cret-pw"), "{err}");
    assert!(err.contains("egress_proxy"), "{err}");
}

#[test]
fn enforcement_defaults_follow_egress_proxy() {
    let none = parse_config_str(&yaml("https://up.example", "")).unwrap();
    assert_eq!(none.egress_enforcement(), None);
    let proxied = parse_config_str(&yaml(
        "https://up.example",
        "egress_proxy: \"http://127.0.0.1:8888\"",
    ))
    .unwrap();
    assert_eq!(
        proxied.egress_enforcement(),
        Some(EgressEnforcement::Pipelock)
    );
    let external =
        parse_config_str(&yaml("https://up.example", "egress:\n  mode: external")).unwrap();
    assert_eq!(
        external.egress_enforcement(),
        Some(EgressEnforcement::External)
    );
}

#[tokio::test]
async fn proxied_route_without_proxy_fails_closed() {
    let up = upstream_ok().await;
    let h = harness(parse_config_str(&yaml(&up.uri(), "")).unwrap()).await;
    let resp = h.server.get("/api/out/x").await;
    assert_eq!(resp.status_code(), 503);
    assert_eq!(
        resp.json::<serde_json::Value>()["error"]["code"],
        "egress_proxy_unconfigured"
    );
    assert!(up.received_requests().await.unwrap().is_empty());
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit WHERE event = 'egress_unenforced'")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn external_mode_proxied_goes_direct() {
    let up = upstream_ok().await;
    let h = harness(parse_config_str(&yaml(&up.uri(), "egress:\n  mode: external")).unwrap()).await;
    let resp = h.server.get("/api/out/x").await;
    assert_eq!(resp.status_code(), 200);
    assert_eq!(up.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn pipelock_mode_uses_proxy() {
    // An HTTP proxy receives absolute-form requests for http:// upstreams,
    // so a mock server stands in for Pipelock. The upstream is unroutable:
    // only the proxy can answer.
    let proxy = upstream_ok().await;
    let config = parse_config_str(&yaml(
        "http://upstream.invalid:9",
        &format!("egress_proxy: \"{}\"", proxy.uri()),
    ))
    .unwrap();
    let h = harness(config).await;
    let resp = h.server.get("/api/out/x").await;
    assert_eq!(resp.status_code(), 200);
    assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
}
