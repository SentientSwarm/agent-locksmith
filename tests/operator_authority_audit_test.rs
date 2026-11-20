//! AGENT-253 — operator authority changes leave an audit trail.
//!
//! A grant change (`agent modify`) records what the allowlist, denylist and
//! expiry were and what they became. A binding change (`set-credential`,
//! stored values, `unset-credential`) writes one operator row naming the
//! route and the binding kind, never a credential value.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::uds::{UdsState, build_router};
use agent_locksmith::auth_v2::{BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::registrations::{Catalog, RegistrationRepository};
use agent_locksmith::repo::{
    AgentCredentialRepository, AgentRepository, BootstrapTokenRepository,
    CredentialSecretsRepository,
};
use agent_locksmith::secret::CredentialSealingKey;
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use axum_test::TestServer;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;

const STORED_VALUE: &str = "audit-canary-value-7f3e";

struct H {
    _dir: TempDir,
    pool: sqlx::SqlitePool,
    admin: TestServer,
    op: String,
    pid: String,
}

async fn setup() -> H {
    let dir = TempDir::new().unwrap();
    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_token.secret.expose().to_string(),
    ))
    .unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{hash}\"\n",
            op_token.public_id.as_str()
        ),
    )
    .unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = agent_locksmith::repo::audit::AuditRepository::new(pool.clone());
    let registrations = Arc::new(RegistrationRepository::new(pool.clone()));
    let catalog = Catalog::from_repo(registrations.as_ref()).await.unwrap();
    let cfg = parse_config_str("listen:\n  host: 127.0.0.1\n  port: 9200\ntools: []\n").unwrap();
    let cfg = Arc::new(ArcSwap::from_pointee(cfg));
    let (pid, _) = agents
        .create("agent-1", None, None, None, None, None)
        .await
        .unwrap();
    let uds = UdsState {
        broker_health: Default::default(),
        admin: Arc::new(AdminService::with_audit(
            agents.clone(),
            BootstrapTokenRepository::new(pool.clone()),
            cfg,
            Some(audit.clone()),
        )),
        agent_auth: Arc::new(BearerAuthenticator::with_audit(agents, Some(audit)).unwrap()),
        operator_auth: Arc::new(OperatorAuthenticator::load(&ops_path).unwrap()),
        operator_mtls: None,
        registrations: Some(registrations),
        catalog: Some(Arc::new(ArcSwap::from_pointee(catalog))),
        resolved_creds: Some(Arc::new(ArcSwap::from_pointee(Default::default()))),
        oauth: None,
        agent_creds: Some(AgentCredentialRepository::new(pool.clone())),
        credential_sealing_key: Some(CredentialSealingKey::generate().unwrap()),
        credential_secrets: Some(CredentialSecretsRepository::new(pool.clone())),
        operational_log: None,
        operational_log_store: None,
        op_resolver: None,
    };
    let h = H {
        _dir: dir,
        pool,
        admin: TestServer::new(build_router(uds)),
        op: format!("Bearer {}", op_token.wire_format()),
        pid,
    };
    for name in ["r", "s"] {
        h.admin
            .put(&format!("/admin/operator/models/{name}"))
            .add_header("authorization", &h.op)
            .json(&json!({ "upstream": "https://up.example", "auth": { "kind": "bearer", "env_var": "UNUSED_KEY" }, "egress": "direct" }))
            .await
            .assert_status_ok();
    }
    h
}

impl H {
    async fn modify(&self, body: Value) {
        self.admin
            .patch(&format!("/admin/operator/agents/{}", self.pid))
            .add_header("authorization", &self.op)
            .json(&body)
            .await
            .assert_status_no_content();
    }

    async fn bind(&self, route: &str, auth_spec: Value) {
        self.admin
            .put(&format!(
                "/admin/operator/agents/{}/credentials/{route}",
                self.pid
            ))
            .add_header("authorization", &self.op)
            .json(&json!({ "auth_spec": auth_spec }))
            .await
            .assert_status_ok();
    }

    /// `(event_class, operator_name, agent_public_id, decision, details)`
    /// for every row of `event`, oldest first.
    async fn rows(&self, event: &str) -> Vec<(String, String, String, String, Value)> {
        let rows: Vec<(String, String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT event_class, operator_name, agent_public_id, decision, details \
             FROM audit WHERE event = ? ORDER BY id",
        )
        .bind(event)
        .fetch_all(&self.pool)
        .await
        .unwrap();
        rows.into_iter()
            .map(|(c, o, a, d, det)| {
                let det = det.map_or(Value::Null, |s| serde_json::from_str(&s).unwrap());
                (c, o, a, d, det)
            })
            .collect()
    }
}

#[tokio::test]
async fn agent_modify_records_allowlist_before_and_after() {
    let h = setup().await;
    h.modify(json!({ "allowlist": ["r"] })).await;
    h.modify(json!({ "allowlist": ["r", "s"], "expires_at": 4_102_444_800_i64 }))
        .await;
    let rows = h.rows("agent_modify").await;
    assert_eq!(rows.len(), 2);
    let (class, op, agent, decision, d) = &rows[1];
    assert_eq!(
        (
            class.as_str(),
            op.as_str(),
            agent.as_str(),
            decision.as_str()
        ),
        ("operator", "alice", h.pid.as_str(), "allowed")
    );
    assert_eq!(d["allowlist"]["before"], json!(["r"]));
    assert_eq!(d["allowlist"]["after"], json!(["r", "s"]));
    assert_eq!(d["expires_at"]["before"], Value::Null);
    assert_eq!(d["expires_at"]["after"], json!(4_102_444_800_i64));
    assert!(
        d.get("denylist").is_none(),
        "untouched fields stay out: {d}"
    );
}

#[tokio::test]
async fn set_credential_records_route_and_binding_kind() {
    let h = setup().await;
    h.modify(json!({ "allowlist": ["r"] })).await;
    h.bind("r", json!({ "kind": "none" })).await;
    h.bind("r", json!({ "kind": "bearer", "env_var": "OTHER_KEY" }))
        .await;
    let rows = h.rows("agent_credential_set").await;
    assert_eq!(rows.len(), 2);
    let (class, op, agent, decision, d) = &rows[1];
    assert_eq!(
        (
            class.as_str(),
            op.as_str(),
            agent.as_str(),
            decision.as_str()
        ),
        ("operator", "alice", h.pid.as_str(), "allowed")
    );
    assert_eq!(d["registration"], "r");
    assert_eq!(d["binding"]["kind"], "bearer");
    assert_eq!(d["previous"]["kind"], "none");
}

#[tokio::test]
async fn stored_credential_records_ref_never_value() {
    let h = setup().await;
    h.modify(json!({ "allowlist": ["r"] })).await;
    let resp = h
        .admin
        .put(&format!(
            "/admin/operator/agents/{}/credentials/r/credential",
            h.pid
        ))
        .add_header("authorization", &h.op)
        .json(&json!({ "value": STORED_VALUE, "bearer": true }))
        .await;
    resp.assert_status_ok();
    let secret_ref = resp.json::<Value>()["secret_ref"]
        .as_str()
        .unwrap()
        .to_string();
    let rows = h.rows("agent_credential_set").await;
    assert_eq!(rows.len(), 1);
    let d = &rows[0].4;
    assert_eq!(d["registration"], "r");
    assert_eq!(d["binding"]["kind"], "stored_bearer");
    assert_eq!(d["binding"]["secret_ref"], secret_ref.as_str());
    let all: Vec<Option<String>> = sqlx::query_scalar("SELECT details FROM audit")
        .fetch_all(&h.pool)
        .await
        .unwrap();
    assert!(
        all.iter().flatten().all(|s| !s.contains(STORED_VALUE)),
        "a stored value reached the audit log"
    );
}

/// AGENT-328: a refused stored write is audited as denied, as the plain
/// set-credential path audits its refusals, and never with the value.
#[tokio::test]
async fn a_refused_stored_credential_is_audited_as_denied() {
    let h = setup().await;
    h.modify(json!({ "allowlist": ["r"] })).await;
    // A binding already in place: a denied row names it, as the plain
    // set-credential path does (AGENT-328).
    h.bind("r", json!({ "kind": "none" })).await;
    let path = format!("/admin/operator/agents/{}/credentials/r/credential", h.pid);
    for body in [
        // `r` names no header, so this would be a stored bearer.
        json!({ "value": "has space" }),
        json!({ "value": STORED_VALUE, "stored_header": true }),
    ] {
        let resp = h
            .admin
            .put(&path)
            .add_header("authorization", &h.op)
            .json(&body)
            .await;
        resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    }
    let rows: Vec<_> = h
        .rows("agent_credential_set")
        .await
        .into_iter()
        .filter(|row| row.3 == "denied")
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    for (class, op, agent, decision, d) in &rows {
        assert_eq!(
            (
                class.as_str(),
                op.as_str(),
                agent.as_str(),
                decision.as_str()
            ),
            ("operator", "alice", h.pid.as_str(), "denied")
        );
        assert_eq!(d["registration"], "r");
        assert_eq!(d["error"], "invalid_stored_credential");
        assert_eq!(d["previous"]["kind"], "none", "{d}");
    }
    let all: Vec<Option<String>> = sqlx::query_scalar("SELECT details FROM audit")
        .fetch_all(&h.pool)
        .await
        .unwrap();
    assert!(
        all.iter()
            .flatten()
            .all(|s| !s.contains(STORED_VALUE) && !s.contains("has space")),
        "a refused value reached the audit log"
    );
}

#[tokio::test]
async fn unset_credential_records_removed_binding() {
    let h = setup().await;
    h.modify(json!({ "allowlist": ["r"] })).await;
    h.bind("r", json!({ "kind": "none" })).await;
    h.admin
        .delete(&format!("/admin/operator/agents/{}/credentials/r", h.pid))
        .add_header("authorization", &h.op)
        .await
        .assert_status_no_content();
    let rows = h.rows("agent_credential_unset").await;
    assert_eq!(rows.len(), 1);
    let (class, _, agent, decision, d) = &rows[0];
    assert_eq!(
        (class.as_str(), agent.as_str(), decision.as_str()),
        ("operator", h.pid.as_str(), "allowed")
    );
    assert_eq!(d["registration"], "r");
    assert_eq!(d["previous"]["kind"], "none");
}
