//! Phase J / M2 (WEM-450, CCS-7/8 + LOG-1..4) — M2 integration suite.
//!
//! One shared substrate (admin UdsState + proxy AppState over one pool,
//! catalog, credential key, sealed store, op resolver, and operational-log
//! emitter/store) proves the M2 slice end to end:
//!   - an op:// credential injects from the resolver cache, and `op` is
//!     never invoked per request (injectable fake resolver);
//!   - a per-agent stored override drives the proxy hot path;
//!   - GET /admin/operator/logs returns operational events, is DISTINCT
//!     from /admin/operator/audit, carries no secret value, and retains
//!     independently of audit.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::app::build_app_full_with_phase_k;
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::operational_log_sink::OperationalLogEmitter;
use agent_locksmith::registrations::{
    AuthSpec, Catalog, Kind, Registration, RegistrationRepository,
};
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository};
use agent_locksmith::repo::{
    AgentCredentialRepository, AgentRepository, BootstrapTokenRepository,
    CredentialSecretsRepository, LogFilter, OperationalLogStore,
};
use agent_locksmith::secret::{OpCommand, OpResolver};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::TempDir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_REF: &str = "op://vault/item/token";
const OP_VALUE: &str = "op-cache-value-123";

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

struct M2 {
    _dir: TempDir,
    admin: TestServer,
    agent: TestServer,
    op_bearer: String,
    agent_bearer: String,
    agent_public_id: String,
    op_calls: Arc<AtomicU64>,
    audit: AuditRepository,
    logs: OperationalLogStore,
    mock: MockServer,
}

async fn setup() -> M2 {
    let dir = TempDir::new().unwrap();

    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_bearer = format!("Bearer {}", op_token.wire_format());
    let token_hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_token.secret.expose().to_string(),
    ))
    .unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_token.public_id.as_str(),
            token_hash
        ),
    )
    .unwrap();

    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let secrets = CredentialSecretsRepository::new(pool.clone());
    let agent_creds = AgentCredentialRepository::new(pool.clone());
    let logs = OperationalLogStore::new(pool.clone());
    let key = agent_locksmith::secret::CredentialSealingKey::generate().unwrap();

    let mock = MockServer::start().await;

    // Two registrations: `op-api` (op custody) + `shared-api` (authless,
    // per-agent override target).
    registrations
        .create(&Registration::new(
            "op-api".to_string(),
            Kind::Model,
            "op custody API".to_string(),
            mock.uri(),
            AuthSpec::OpBearer {
                reference: OP_REF.to_string(),
            },
        ))
        .await
        .unwrap();
    registrations
        .create(&Registration::new(
            "shared-api".to_string(),
            Kind::Model,
            "shared API".to_string(),
            mock.uri(),
            AuthSpec::None,
        ))
        .await
        .unwrap();

    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let catalog_arc = Arc::new(ArcSwap::from_pointee(catalog));
    let resolved_arc = Arc::new(ArcSwap::from_pointee(Default::default()));

    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\ntools: []\n").unwrap();
    let cfg_arc = Arc::new(ArcSwap::from_pointee(cfg));

    let (pid, secret) = agents
        .create(
            "agent-1",
            None,
            Some(&["op-api".to_string(), "shared-api".to_string()]),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let agent_bearer = format!("Bearer lk_{pid}.{}", secret.expose_secret());
    let agent_public_id = agents
        .get_by_name("agent-1")
        .await
        .unwrap()
        .unwrap()
        .public_id;

    let bearer_concrete =
        Arc::new(BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap());
    let bearer_dyn: Arc<dyn AgentAuthenticator> = bearer_concrete.clone();
    let operator_auth = Arc::new(OperatorAuthenticator::load(&ops_path).unwrap());

    // Operational-log emitter + drain over the shared store.
    let emitter = Arc::new(OperationalLogEmitter::spawn(logs.clone(), 64));

    let admin_service = Arc::new(
        AdminService::with_audit_and_creds(
            agents,
            bootstrap,
            cfg_arc.clone(),
            Some(audit.clone()),
            resolved_arc.clone(),
        )
        .with_operational_log(emitter.clone()),
    );

    // op resolver with counting fake — resolve OP_REF only.
    let op_calls = Arc::new(AtomicU64::new(0));
    let resolver = OpResolver::new(
        Box::new(CountingFakeOp {
            values: HashMap::from([(OP_REF.to_string(), OP_VALUE.to_string())]),
            calls: op_calls.clone(),
        }),
        Some(emitter.clone()),
    );
    resolver.refresh(&[OP_REF.to_string()]);
    let op_resolver = Arc::new(resolver);

    let uds = UdsState {
        admin: admin_service,
        agent_auth: bearer_concrete,
        operator_auth,
        operator_mtls: None,
        registrations: Some(registrations.clone()),
        catalog: Some(catalog_arc.clone()),
        resolved_creds: Some(resolved_arc.clone()),
        oauth: None,
        agent_creds: Some(agent_creds.clone()),
        credential_sealing_key: Some(key.clone()),
        credential_secrets: Some(secrets.clone()),
        operational_log: Some(emitter.clone()),
        operational_log_store: Some(logs.clone()),
    };
    let admin = TestServer::new(build_router(uds));

    let agent_router = build_app_full_with_phase_k(
        cfg_arc,
        Some(audit.clone()),
        resolved_arc,
        None,
        Some(bearer_dyn),
        Some(registrations),
        catalog_arc,
        None,
        Some(agent_creds),
        Some(key),
        Some(secrets),
        Some(emitter),
        Some(op_resolver),
    );
    let agent = TestServer::new(agent_router);

    M2 {
        _dir: dir,
        admin,
        agent,
        op_bearer,
        agent_bearer,
        agent_public_id,
        op_calls,
        audit,
        logs,
        mock,
    }
}

/// Poll the operational-log store until at least `n` rows are drained.
async fn wait_for_logs(store: &OperationalLogStore, n: usize) -> Vec<serde_json::Value> {
    for _ in 0..100 {
        let rows = store.query(&LogFilter::default()).await.unwrap();
        if rows.len() >= n {
            return rows
                .into_iter()
                .map(|r| json!({ "component": r.component, "event": r.event, "level": r.level }))
                .collect();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {n} operational-log rows");
}

#[tokio::test]
async fn m2_full_slice() {
    let h = setup().await;

    // ── op:// injects from cache; op never invoked per request ──────────
    let calls_before = h.op_calls.load(Ordering::Relaxed);
    assert_eq!(calls_before, 1, "one op invocation at refresh time");

    Mock::given(method("GET"))
        .and(path("/op/ping"))
        .and(header("authorization", format!("Bearer {OP_VALUE}")))
        .respond_with(ResponseTemplate::new(200).set_body_string("op-ok"))
        .mount(&h.mock)
        .await;
    let resp = h
        .agent
        .get("/api/op-api/op/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "op-ok");
    assert_eq!(
        h.op_calls.load(Ordering::Relaxed),
        calls_before,
        "op must not be shelled out on the hot path"
    );

    // ── per-agent stored override drives the proxy ──────────────────────
    const OVERRIDE_SECRET: &str = "override-secret-abc";
    h.admin
        .put(&format!(
            "/admin/operator/agents/{}/credentials/shared-api/credential",
            h.agent_public_id
        ))
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "value": OVERRIDE_SECRET }))
        .await
        .assert_status_ok();

    Mock::given(method("GET"))
        .and(path("/shared/ping"))
        .and(header("authorization", format!("Bearer {OVERRIDE_SECRET}")))
        .respond_with(ResponseTemplate::new(200).set_body_string("shared-ok"))
        .mount(&h.mock)
        .await;
    let resp = h
        .agent
        .get("/api/shared-api/shared/ping")
        .add_header("authorization", &h.agent_bearer)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "shared-ok");

    // ── generate an operational-log event via a registry mutation ───────
    h.admin
        .put("/admin/operator/models/newmodel")
        .add_header("authorization", &h.op_bearer)
        .json(&json!({ "upstream": h.mock.uri(), "auth": { "kind": "none" } }))
        .await
        .assert_status_ok();
    // Drain: at least the registry event lands (config_loaded isn't emitted
    // in this test harness since we build routers directly).
    let drained = wait_for_logs(&h.logs, 1).await;
    assert!(
        drained.iter().any(|r| r["component"] == "registry"),
        "expected a registry operational-log event, got {drained:?}"
    );

    // ── /logs is DISTINCT from /audit ───────────────────────────────────
    let logs_body: serde_json::Value = h
        .admin
        .get("/admin/operator/logs")
        .add_header("authorization", &h.op_bearer)
        .await
        .json();
    let logs_arr = logs_body["logs"].as_array().unwrap();
    assert!(!logs_arr.is_empty());
    // Operational-log rows carry `component`; audit rows carry `event_class`.
    assert!(logs_arr.iter().all(|r| r.get("component").is_some()));
    assert!(logs_arr.iter().all(|r| r.get("event_class").is_none()));

    let audit_body: serde_json::Value = h
        .admin
        .get("/admin/operator/audit")
        .add_header("authorization", &h.op_bearer)
        .await
        .json();
    let audit_arr = audit_body["events"].as_array().unwrap();
    // The two proxied requests produced audit rows.
    assert!(
        audit_arr.iter().any(|r| r["event"] == "proxy_request"),
        "audit should have proxy_request rows"
    );
    // Audit rows carry `event_class` and no operational `component`.
    assert!(audit_arr.iter().all(|r| r.get("event_class").is_some()));

    // ── operational-log stream carries NO secret value (LOG-4) ──────────
    let logs_text = serde_json::to_string(&logs_body).unwrap();
    assert!(
        !logs_text.contains(OVERRIDE_SECRET) && !logs_text.contains(OP_VALUE),
        "operational-log response must not contain any credential value"
    );
    // Belt-and-suspenders: audit must not either.
    let audit_text = serde_json::to_string(&audit_body).unwrap();
    assert!(!audit_text.contains(OVERRIDE_SECRET) && !audit_text.contains(OP_VALUE));

    // ── independent retention: sweeping logs leaves audit intact ────────
    let audit_rows_before = h
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap()
        .len();
    assert!(audit_rows_before > 0);
    let swept = h.logs.sweep(i64::MAX).await.unwrap();
    assert!(swept > 0, "operational-log sweep removed the log rows");
    assert!(
        h.logs
            .query(&LogFilter::default())
            .await
            .unwrap()
            .is_empty(),
        "operational logs cleared"
    );
    let audit_rows_after = h
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap()
        .len();
    assert_eq!(
        audit_rows_before, audit_rows_after,
        "sweeping operational logs must not touch the audit stream"
    );
}
