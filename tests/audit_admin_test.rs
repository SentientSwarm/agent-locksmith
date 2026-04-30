//! T3.2 — AdminService records audit rows for state-mutating calls.
//!
//! event_class=operator, identifying the operator (or "agent" for self-
//! service rotate/deregister/register-via-bootstrap). Failures emit
//! decision=denied (auth/conflict) or error (backend).

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::service::{CreateAgentInput, MintBootstrapInput, RegisterInput};
use agent_locksmith::auth_v2::{AgentIdentity, OperatorIdentity};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository, Decision, EventClass};
use agent_locksmith::repo::{AgentRepository, BootstrapTokenRepository};
use arc_swap::ArcSwap;
use secrecy::SecretString;
use std::sync::Arc;
use tempfile::TempDir;

struct Fixture {
    _dir: TempDir,
    admin: AdminService,
    audit: AuditRepository,
}

async fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool.clone());
    let audit = AuditRepository::new(pool);
    let cfg = parse_config_str(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#,
    )
    .unwrap();
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let admin = AdminService::with_audit(agents, bootstrap, config, Some(audit.clone()));
    Fixture {
        _dir: dir,
        admin,
        audit,
    }
}

fn op() -> OperatorIdentity {
    OperatorIdentity {
        name: "alice".into(),
        scope: None,
    }
}

#[tokio::test]
async fn create_agent_as_operator_emits_audit_row() {
    let f = fixture().await;
    let result = f
        .admin
        .create_agent_as_operator(
            &op(),
            CreateAgentInput {
                name: "agent-a".into(),
                description: None,
                allowlist: None,
                denylist: None,
                metadata: None,
                expires_at: None,
            },
        )
        .await
        .expect("create ok");

    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.event_class, EventClass::Operator);
    assert_eq!(row.event, "agent_create");
    assert_eq!(row.operator_name.as_deref(), Some("alice"));
    assert_eq!(
        row.agent_public_id.as_deref(),
        Some(result.public_id.as_str())
    );
    assert_eq!(row.decision, Decision::Allowed);
}

#[tokio::test]
async fn revoke_agent_emits_audit_row() {
    let f = fixture().await;
    let created = f
        .admin
        .create_agent_as_operator(
            &op(),
            CreateAgentInput {
                name: "agent-r".into(),
                description: None,
                allowlist: None,
                denylist: None,
                metadata: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
    f.admin
        .revoke_agent(&op(), &created.public_id)
        .await
        .unwrap();

    // T3.11 review: agent_revoke is event_class=security (revocation
    // changes the agent's trust posture).
    let rows = f
        .audit
        .query(
            &AuditFilter {
                event_class: Some(EventClass::Security),
                ..AuditFilter::default()
            },
            AuditPage::default(),
        )
        .await
        .unwrap();
    let revoke_row = rows.iter().find(|r| r.event == "agent_revoke");
    let row = revoke_row.expect("agent_revoke audit row exists in Security class");
    assert_eq!(row.operator_name.as_deref(), Some("alice"));
    assert_eq!(
        row.agent_public_id.as_deref(),
        Some(created.public_id.as_str())
    );
    assert_eq!(row.decision, Decision::Allowed);
}

#[tokio::test]
async fn mint_bootstrap_emits_audit_row() {
    let f = fixture().await;
    let minted = f
        .admin
        .mint_bootstrap_token(
            &op(),
            MintBootstrapInput {
                tool_allowlist: Some(vec!["github".into()]),
                expires_at: None,
                single_use: true,
            },
        )
        .await
        .unwrap();

    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.event, "bootstrap_mint");
    assert_eq!(row.operator_name.as_deref(), Some("alice"));
    assert_eq!(row.decision, Decision::Allowed);
    let details = row.details.as_ref().unwrap();
    assert_eq!(
        details["bootstrap_public_id"].as_str(),
        Some(minted.public_id.as_str())
    );
}

#[tokio::test]
async fn register_via_bootstrap_emits_audit_row() {
    let f = fixture().await;
    let minted = f
        .admin
        .mint_bootstrap_token(
            &op(),
            MintBootstrapInput {
                tool_allowlist: None,
                expires_at: None,
                single_use: true,
            },
        )
        .await
        .unwrap();
    let registered = f
        .admin
        .register_agent(RegisterInput {
            bootstrap_token: SecretString::from(minted.token.clone()),
            name: "agent-b".into(),
            description: None,
            metadata: None,
        })
        .await
        .unwrap();

    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r.event == "agent_register")
        .expect("agent_register row");
    assert_eq!(row.event_class, EventClass::Operator);
    assert_eq!(
        row.agent_public_id.as_deref(),
        Some(registered.public_id.as_str())
    );
    assert_eq!(row.decision, Decision::Allowed);
}

#[tokio::test]
async fn agent_name_conflict_records_denied_row() {
    let f = fixture().await;
    f.admin
        .create_agent_as_operator(
            &op(),
            CreateAgentInput {
                name: "dup".into(),
                description: None,
                allowlist: None,
                denylist: None,
                metadata: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
    let err = f
        .admin
        .create_agent_as_operator(
            &op(),
            CreateAgentInput {
                name: "dup".into(),
                description: None,
                allowlist: None,
                denylist: None,
                metadata: None,
                expires_at: None,
            },
        )
        .await;
    assert!(err.is_err(), "second create must fail with name conflict");

    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let denied = rows.iter().find(|r| r.decision == Decision::Denied);
    let row = denied.expect("conflict creates a Denied row");
    assert_eq!(row.event, "agent_create");
    assert!(
        row.details.as_ref().and_then(|d| d.get("error")).is_some(),
        "denied row carries an error detail"
    );
}

#[tokio::test]
async fn rotate_agent_emits_audit_row() {
    let f = fixture().await;
    let created = f
        .admin
        .create_agent_as_operator(
            &op(),
            CreateAgentInput {
                name: "agent-rot".into(),
                description: None,
                allowlist: None,
                denylist: None,
                metadata: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
    let secret = created.token.split_once('.').unwrap().1.to_string();
    let agent = AgentIdentity {
        public_id: created.public_id.clone(),
        name: "agent-rot".into(),
        tool_allowlist: None,
        tool_denylist: None,
    };
    f.admin
        .rotate_agent(&agent, &SecretString::from(secret))
        .await
        .unwrap();

    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r.event == "agent_rotate")
        .expect("agent_rotate row");
    assert_eq!(
        row.agent_public_id.as_deref(),
        Some(created.public_id.as_str())
    );
    assert_eq!(row.decision, Decision::Allowed);
}

#[tokio::test]
async fn admin_service_without_audit_repo_does_not_panic() {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("db.sqlite"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool);
    let cfg = parse_config_str(
        r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#,
    )
    .unwrap();
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let admin = AdminService::new(agents, bootstrap, config);
    admin
        .create_agent_as_operator(
            &op(),
            CreateAgentInput {
                name: "no-audit".into(),
                description: None,
                allowlist: None,
                denylist: None,
                metadata: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
}
