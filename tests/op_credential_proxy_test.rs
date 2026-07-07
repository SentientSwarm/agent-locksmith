//! Phase J / M2 (WEM-444, CCS-8) — proxy hot-path `op://` injection.
//!
//! When a registration uses the `op` custody backend, the proxy reads the
//! value from the OpResolver cache (populated out-of-band at startup) and
//! injects it — it NEVER shells `op` per request. Covers:
//!   - cache hit → upstream sees the injected credential;
//!   - the `op` command is invoked zero times during the request (only at
//!     refresh time);
//!   - a cache miss → loud 503 `credential_unresolved`.

use agent_locksmith::app::build_app_full_with_phase_k;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::AuditRepository;
use agent_locksmith::secret::{OpCommand, OpResolver};
use arc_swap::ArcSwap;
use axum::Router;
use axum_test::TestServer;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Fake `op` CLI: resolves from a map and counts every invocation so the
/// test can prove the hot path never shells out.
struct CountingFakeOp {
    values: HashMap<String, String>,
    calls: Arc<AtomicU64>,
}

impl OpCommand for CountingFakeOp {
    fn read(&self, reference: &str) -> Result<SecretString, String> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match self.values.get(reference) {
            Some(v) => Ok(SecretString::from(v.clone())),
            None => Err("item not found".to_string()),
        }
    }
}

struct Harness {
    _dir: TempDir,
    server: TestServer,
    agent_bearer: String,
    mock: MockServer,
    op_calls: Arc<AtomicU64>,
}

/// Build a proxy harness with a single `op-api` registration carrying
/// `auth`. `resolve_ref` (when Some) is the (reference, value) the fake
/// `op` will resolve at refresh time; None leaves the cache empty (cache
/// miss path).
async fn setup(auth: AuthSpec, resolve: Option<(&str, &str)>) -> Harness {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));

    let mock = MockServer::start().await;

    let r = Registration::new(
        "op-api".to_string(),
        Kind::Model,
        "op custody API (test)".to_string(),
        mock.uri(),
        auth,
    );
    registrations.create(&r).await.unwrap();

    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));
    let resolved_arc = Arc::new(ArcSwap::from_pointee(Default::default()));

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    let (pid, secret) = agents
        .create(
            "agent-1",
            None,
            Some(&["op-api".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let agent_bearer = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents, Some(audit.clone())).unwrap());

    // Build the resolver with the counting fake + refresh it out-of-band.
    let op_calls = Arc::new(AtomicU64::new(0));
    let mut values = HashMap::new();
    let mut refs = Vec::new();
    if let Some((reference, value)) = resolve {
        values.insert(reference.to_string(), value.to_string());
        refs.push(reference.to_string());
    }
    let resolver = OpResolver::new(
        Box::new(CountingFakeOp {
            values,
            calls: op_calls.clone(),
        }),
        None,
    );
    resolver.refresh(&refs);
    let op_resolver = Arc::new(resolver);

    let app: Router = build_app_full_with_phase_k(
        cfg_arc,
        Some(audit),
        resolved_arc,
        None,
        Some(bearer),
        Some(registrations),
        catalog_arc,
        None,
        None,
        None,
        None,
        None,
        Some(op_resolver),
    );
    let server = TestServer::new(app);

    Harness {
        _dir: dir,
        server,
        agent_bearer,
        mock,
        op_calls,
    }
}

#[tokio::test]
async fn op_bearer_injects_cached_value_and_op_never_runs_per_request() {
    let reference = "op://vault/item/field";
    let h = setup(
        AuthSpec::OpBearer {
            reference: reference.to_string(),
        },
        Some((reference, "op-resolved-token")),
    )
    .await;

    // Exactly one invocation happened at refresh time.
    let after_refresh = h.op_calls.load(Ordering::Relaxed);
    assert_eq!(after_refresh, 1);

    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer op-resolved-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .get("/api/op-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "ok");

    // The request injected from cache — `op` was NOT invoked again.
    assert_eq!(
        h.op_calls.load(Ordering::Relaxed),
        after_refresh,
        "op must never be invoked on the hot path"
    );
}

#[tokio::test]
async fn op_header_injects_cached_value_upstream() {
    let reference = "op://vault/item/apikey";
    let h = setup(
        AuthSpec::OpHeader {
            header: "x-api-key".to_string(),
            reference: reference.to_string(),
        },
        Some((reference, "op-resolved-apikey")),
    )
    .await;

    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("x-api-key", "op-resolved-apikey"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .get("/api/op-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn op_cache_miss_returns_503_credential_unresolved() {
    // Registration references op://.../missing, but the resolver cache is
    // empty (refresh resolved nothing) → loud 503, never a silent forward.
    let h = setup(
        AuthSpec::OpBearer {
            reference: "op://vault/item/missing".to_string(),
        },
        None,
    )
    .await;

    let resp = h
        .server
        .get("/api/op-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "credential_unresolved");
}
