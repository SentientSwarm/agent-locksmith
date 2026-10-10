//! Phase J (WEM-439, CCS-5) — proxy hot-path stored-credential injection.
//!
//! When a registration uses the `stored` custody backend, the proxy fetches
//! the sealed value from `credential_secrets` and unseals it with the
//! credential sealing key before forwarding upstream. Covers:
//!
//!   - stored_bearer → upstream sees `Authorization: Bearer <unsealed>`;
//!   - stored_header → upstream sees `<header>: <unsealed>`;
//!   - a missing / tombstoned secret_ref → loud 503 `credential_unresolved`
//!     (never a silent forward without the credential);
//!   - key unset with a stored registration → 503 `credential_unresolved`.

use agent_locksmith::app::build_app_full_with_phase_j;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::CredentialSecretsRepository;
use agent_locksmith::repo::audit::AuditRepository;
use agent_locksmith::secret::CredentialSealingKey;
use arc_swap::ArcSwap;
use axum::Router;
use axum_test::TestServer;
use secrecy::ExposeSecret;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Harness {
    _dir: TempDir,
    server: TestServer,
    agent_bearer: String,
    mock: MockServer,
    /// Sealed-secret store on the same DB the app uses — lets a test seal a
    /// value (minting a live `secret_ref`) that the proxy hot path can see.
    secrets: CredentialSecretsRepository,
}

/// Build a proxy harness whose single registration `store-api` carries
/// `auth`. `wire_key` toggles the credential sealing key + sealed store into
/// the app (false exercises the "feature off = fail loud" path). The
/// returned harness exposes a `secrets` store on the same DB so a test can
/// pre-seal a value before (or instead of) issuing the request.
async fn setup(auth: AuthSpec, wire_key: bool) -> Harness {
    let dir = TempDir::new().unwrap();
    let key = CredentialSealingKey::generate().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let secrets = CredentialSecretsRepository::new(pool.clone());

    let mock = MockServer::start().await;

    let r = Registration::new(
        "store-api".to_string(),
        Kind::Model,
        "Stored-credential API (test)".to_string(),
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
            Some(&["store-api".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let agent_bearer = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents, Some(audit.clone())).unwrap());

    let (app_key, app_secrets) = if wire_key {
        (Some(key.clone()), Some(secrets.clone()))
    } else {
        (None, None)
    };

    let app: Router = build_app_full_with_phase_j(
        cfg_arc,
        Some(audit),
        resolved_arc,
        None,
        Some(bearer),
        Some(registrations),
        catalog_arc,
        None,
        None,
        app_key,
        app_secrets,
    );
    let server = TestServer::new(app);

    Harness {
        _dir: dir,
        server,
        agent_bearer,
        mock,
        secrets,
    }
}

/// Build a harness whose registration references a freshly-sealed value.
/// Two-phase: seal into the store to mint a ref, then build the app against
/// the SAME pool so the sealed row is live on the proxy hot path.
async fn setup_with_sealed(value: &[u8], make_auth: impl Fn(String) -> AuthSpec) -> Harness {
    // Phase 1: stand up the store + seal a value to mint a ref.
    let dir = TempDir::new().unwrap();
    let key = CredentialSealingKey::generate().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let secrets = CredentialSecretsRepository::new(pool.clone());
    let (ct, nonce) = key.seal(value).unwrap();
    let secret_ref = secrets.insert(&ct, &nonce).await.unwrap();

    // Phase 2: build the app against the SAME pool so the sealed row is live.
    build_harness_on(dir, pool, key, make_auth(secret_ref), true).await
}

/// Shared builder used by both entry points once a `pool` (and any pre-sealed
/// rows) exist.
async fn build_harness_on(
    dir: TempDir,
    pool: sqlx::SqlitePool,
    key: CredentialSealingKey,
    auth: AuthSpec,
    wire_key: bool,
) -> Harness {
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let secrets = CredentialSecretsRepository::new(pool.clone());

    let mock = MockServer::start().await;

    let r = Registration::new(
        "store-api".to_string(),
        Kind::Model,
        "Stored-credential API (test)".to_string(),
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
            Some(&["store-api".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let agent_bearer = format!("Bearer lk_{pid}.{}", secret.expose_secret());

    let bearer: Arc<dyn AgentAuthenticator> =
        Arc::new(BearerAuthenticator::with_audit(agents, Some(audit.clone())).unwrap());

    let (app_key, app_secrets) = if wire_key {
        (Some(key.clone()), Some(secrets.clone()))
    } else {
        (None, None)
    };

    let app: Router = build_app_full_with_phase_j(
        cfg_arc,
        Some(audit),
        resolved_arc,
        None,
        Some(bearer),
        Some(registrations),
        catalog_arc,
        None,
        None,
        app_key,
        app_secrets,
    );
    let server = TestServer::new(app);

    Harness {
        _dir: dir,
        server,
        agent_bearer,
        mock,
        secrets,
    }
}

// ─── stored_bearer → upstream sees the unsealed bearer token ────────────────
#[tokio::test]
async fn stored_bearer_injects_unsealed_value_upstream() {
    let h = setup_with_sealed(b"unsealed-bearer-xyz", |secret_ref| {
        AuthSpec::StoredBearer { secret_ref }
    })
    .await;

    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer unsealed-bearer-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .get("/api/store-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "ok");
}

// ─── stored_header → upstream sees the unsealed value under the header ───────
#[tokio::test]
async fn stored_header_injects_unsealed_value_upstream() {
    let h = setup_with_sealed(b"unsealed-apikey-abc", |secret_ref| {
        AuthSpec::StoredHeader {
            header: "x-api-key".to_string(),
            secret_ref,
        }
    })
    .await;

    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("x-api-key", "unsealed-apikey-abc"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&h.mock)
        .await;

    let resp = h
        .server
        .get("/api/store-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status_ok();
}

// ─── missing secret_ref → loud 503 credential_unresolved ────────────────────
#[tokio::test]
async fn missing_ref_returns_503_credential_unresolved() {
    let h = setup(
        AuthSpec::StoredBearer {
            secret_ref: "cs_does_not_exist".to_string(),
        },
        true,
    )
    .await;

    let resp = h
        .server
        .get("/api/store-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "credential_unresolved");
}

// ─── tombstoned secret_ref → loud 503 (rotated / cleared out) ───────────────
#[tokio::test]
async fn tombstoned_ref_returns_503() {
    // Seal + wire a live ref, then tombstone it out from under the request.
    let dir = TempDir::new().unwrap();
    let key = CredentialSealingKey::generate().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let secrets = CredentialSecretsRepository::new(pool.clone());
    let (ct, nonce) = key.seal(b"soon-gone").unwrap();
    let secret_ref = secrets.insert(&ct, &nonce).await.unwrap();

    let h = build_harness_on(
        dir,
        pool,
        key,
        AuthSpec::StoredBearer {
            secret_ref: secret_ref.clone(),
        },
        true,
    )
    .await;
    // Tombstone the live row → invisible to the hot path's get.
    h.secrets.tombstone(&secret_ref).await.unwrap();

    let resp = h
        .server
        .get("/api/store-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "credential_unresolved");
}

// ─── key unset with a stored registration → 503 (feature off = fail loud) ────
#[tokio::test]
async fn key_unset_with_stored_registration_returns_503() {
    // A live ref exists in the DB, but the app is built WITHOUT the sealing
    // key + store, so the hot path can't resolve it → loud 503.
    let dir = TempDir::new().unwrap();
    let key = CredentialSealingKey::generate().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let secrets = CredentialSecretsRepository::new(pool.clone());
    let (ct, nonce) = key.seal(b"never-injected").unwrap();
    let secret_ref = secrets.insert(&ct, &nonce).await.unwrap();

    let h = build_harness_on(dir, pool, key, AuthSpec::StoredBearer { secret_ref }, false).await;

    let resp = h
        .server
        .get("/api/store-api/v1/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["error"]["code"], "credential_unresolved");
}
