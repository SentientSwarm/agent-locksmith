//! T6.10 — auth_method is populated on every authenticated audit row.
//!
//! Pinned cases for v0.7.0:
//! - Operator-initiated admin operations record `auth_method = "operator"`.
//! - Agent self-service paths record `auth_method = "agent"`.
//! - Bootstrap-token register records `auth_method = "bootstrap"` (D-10).
//! - Proxy hot path records `auth_method = "bearer"` (M2 default).
//! - mTLS-authenticated paths land in M6 Session B's listener wiring;
//!   the validator's audit-on-failure already records `mtls`. Tested
//!   directly in `tests/mtls_authenticator_test.rs`.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::service::{CreateAgentInput, MintBootstrapInput, RegisterInput};
use agent_locksmith::auth_v2::OperatorIdentity;
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository};
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
        auth_method: None,
    }
}

#[tokio::test]
async fn operator_create_records_auth_method_operator() {
    let f = fixture().await;
    f.admin
        .create_agent_as_operator(
            &op(),
            CreateAgentInput {
                name: "agent-x".into(),
                description: None,
                allowlist: None,
                denylist: None,
                metadata: None,
                expires_at: None,
            },
        )
        .await
        .unwrap();
    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    let row = rows.iter().find(|r| r.event == "agent_create").unwrap();
    assert_eq!(row.auth_method.as_deref(), Some("operator"));
}

#[tokio::test]
async fn bootstrap_register_records_auth_method_bootstrap() {
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
    f.admin
        .register_agent(RegisterInput {
            bootstrap_token: SecretString::from(minted.token.clone()),
            name: "bootstrapped".into(),
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
    let row = rows.iter().find(|r| r.event == "agent_register").unwrap();
    assert_eq!(row.auth_method.as_deref(), Some("bootstrap"));
}
