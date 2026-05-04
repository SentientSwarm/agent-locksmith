//! M9 / B1 follow-up — agent skill endpoints (`/skill` unauthenticated,
//! `/agent/skill` authenticated).

use agent_locksmith::app::build_app_full;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::AuditRepository;
use agent_locksmith::secret::resolve_tool_creds_sync_env_only;
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tempfile::TempDir;

const YAML: &str = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools:
  - name: "things"
    description: "Things service for tests"
    upstream: "http://example.invalid"
    timeouts: { request_seconds: 5, idle_seconds: 5 }
  - name: "secret-tool"
    description: "Tool the test agent shouldn't see"
    upstream: "http://example.invalid"
    timeouts: { request_seconds: 5, idle_seconds: 5 }
"#;

async fn server_with_agent(
    allowlist: Option<Vec<String>>,
) -> (TempDir, TestServer, String /* bearer header value */) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool);
    let allow_ref = allowlist.as_deref();
    let (pid, secret) = agents
        .create("skill-test-agent", None, allow_ref, None, None, None)
        .await
        .unwrap();
    let bearer: Arc<dyn AgentAuthenticator> = Arc::new(
        BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap(),
    );
    let cfg = parse_config_str(YAML).unwrap();
    let resolved = resolve_tool_creds_sync_env_only(&cfg);
    let shared = Arc::new(ArcSwap::from_pointee(cfg));
    let app = build_app_full(
        shared,
        Some(audit),
        Arc::new(ArcSwap::from_pointee(resolved)),
        None,
        Some(bearer),
    );
    let server = TestServer::new(app);
    let header = format!("Bearer lk_{pid}.{}", secret.expose_secret());
    (dir, server, header)
}

// /skill (unauthenticated) returns the generic markdown with no
// tool/model leak, advertises the personalized form, and uses
// public/cacheable Cache-Control.
#[tokio::test]
async fn unauthenticated_skill_returns_generic_markdown() {
    let (_dir, server, _bearer) = server_with_agent(Some(vec!["things".into()])).await;
    let resp = server.get("/skill").await;
    resp.assert_status_ok();

    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "text/markdown; charset=utf-8");

    let cache = resp
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cache.contains("public") && cache.contains("max-age"),
        "unauth /skill must be cacheable; got Cache-Control={cache}"
    );

    let body = resp.text();
    assert!(body.starts_with("---\n"), "agentskills.io frontmatter present");
    assert!(body.contains("name: locksmith"));
    // Must NOT leak tool names from the active deployment.
    assert!(
        !body.contains("things"),
        "unauth /skill must not include tool names"
    );
    assert!(
        !body.contains("secret-tool"),
        "unauth /skill must not include tool names"
    );
    // Must advertise the personalized form so callers know to upgrade.
    assert!(
        body.contains("personalized"),
        "unauth form must advertise the personalized form"
    );
    assert!(
        body.contains("Authorization: Bearer"),
        "unauth form must show how to authenticate"
    );
}

// /skill with a valid bearer returns the personalized form (single
// auth-optional route — was previously /agent/skill, collapsed in the
// M9 follow-up so the documented "GET /skill with your bearer" recipe
// actually works).
#[tokio::test]
async fn skill_with_valid_bearer_returns_personalized_markdown() {
    let (_dir, server, bearer) = server_with_agent(Some(vec!["things".into()])).await;
    let resp = server
        .get("/skill")
        .add_header("Authorization", bearer)
        .await;
    resp.assert_status_ok();

    let ct = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "text/markdown; charset=utf-8");

    let cache = resp
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cache.contains("private") && cache.contains("no-cache"),
        "personalized /skill must NOT be cacheable; got Cache-Control={cache}"
    );

    let body = resp.text();
    // Generic template at the top.
    assert!(body.contains("name: locksmith"));
    // Personalized section with the agent's name.
    assert!(body.contains("skill-test-agent"));
    assert!(body.contains("Personalized for"));
    // Allowed tool appears with description.
    assert!(body.contains("`things`"));
    assert!(body.contains("Things service for tests"));
    // Tool the agent ISN'T allowed to see must NOT appear.
    assert!(
        !body.contains("secret-tool"),
        "personalized form must filter by ACL; got body containing secret-tool"
    );
    // Audit-debug recipe scoped to this agent.
    assert!(body.contains("locksmith audit query"));
}

// /skill with a malformed/invalid bearer → 401. We don't silently
// downgrade to the generic form: that would let an attacker probe
// valid token formats by checking content variation.
#[tokio::test]
async fn skill_with_invalid_bearer_returns_401() {
    let (_dir, server, _bearer) = server_with_agent(Some(vec!["things".into()])).await;
    let resp = server
        .get("/skill")
        .add_header("Authorization", "Bearer not_a_valid_token")
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    // §4.7.9 envelope (consistent with /api/... and /tools).
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["type"], "auth_error");
    assert_eq!(body["error"]["code"], "invalid_credential");
}

// Sanity: /agent/skill is gone (the route was collapsed into auth-
// optional /skill). Should 404, not silently fall through.
#[tokio::test]
async fn legacy_agent_skill_route_is_removed() {
    let (_dir, server, bearer) = server_with_agent(Some(vec!["things".into()])).await;
    let resp = server
        .get("/agent/skill")
        .add_header("Authorization", bearer)
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}
