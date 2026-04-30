//! T3.4 — INF-13 audit-on-failure. Failed authentications and bootstrap
//! reuse attempts emit event_class=security audit rows.

use agent_locksmith::admin::AdminService;
use agent_locksmith::admin::service::{MintBootstrapInput, RegisterInput};
use agent_locksmith::auth_v2::{AgentAuthenticator, BearerAuthenticator, OperatorAuthenticator};
use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::audit::{AuditFilter, AuditPage, AuditRepository, Decision, EventClass};
use agent_locksmith::repo::{AgentRepository, BootstrapTokenRepository};
use agent_locksmith::{argon2_helper, token};
use arc_swap::ArcSwap;
use secrecy::SecretString;
use std::sync::Arc;
use tempfile::TempDir;

struct AuthFixture {
    _dir: TempDir,
    audit: AuditRepository,
    agents: AgentRepository,
    bearer: BearerAuthenticator,
}

async fn auth_fixture() -> AuthFixture {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let agents = AgentRepository::new(pool.clone());
    let audit = AuditRepository::new(pool);
    let bearer = BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone())).unwrap();
    AuthFixture {
        _dir: dir,
        audit,
        agents,
        bearer,
    }
}

#[tokio::test]
async fn unknown_agent_token_emits_security_audit_row() {
    let f = auth_fixture().await;
    let bogus = token::StructuredToken::generate(token::TokenNamespace::Agent);
    let header = format!("Bearer {}", bogus.wire_format());
    let err = f
        .bearer
        .authenticate_bearer(&header)
        .await
        .expect_err("unknown id => invalid credential");
    let _ = err;

    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "one security row per failed auth");
    let row = &rows[0];
    assert_eq!(row.event_class, EventClass::Security);
    assert_eq!(row.event, "auth_failure");
    assert_eq!(row.decision, Decision::Denied);
    assert_eq!(row.auth_method.as_deref(), Some("bearer"));
}

#[tokio::test]
async fn malformed_agent_token_emits_security_audit_row() {
    let f = auth_fixture().await;
    let err = f
        .bearer
        .authenticate_bearer("Bearer not-a-token")
        .await
        .expect_err("malformed token");
    let _ = err;

    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_class, EventClass::Security);
    assert_eq!(rows[0].event, "auth_failure");
}

#[tokio::test]
async fn missing_authorization_header_emits_no_row() {
    // MissingCredential is not a security event — agents may probe
    // unauthenticated endpoints. Only credentials that fail validation
    // emit audit rows. (If a deployment wants to log every probe, that's
    // an access-log concern, not an audit one.)
    let f = auth_fixture().await;
    let err = f.bearer.authenticate_bearer("").await.expect_err("missing");
    let _ = err;
    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "missing-credential is not a security event"
    );
}

#[tokio::test]
async fn wrong_secret_emits_security_audit_row() {
    let f = auth_fixture().await;
    // Create an agent so the public_id is real but use a different secret.
    let (pid, _real_secret) = f
        .agents
        .create("agent-x", None, None, None, None, None)
        .await
        .unwrap();
    // 43-char base64-no-pad secret — same shape as a real one but with
    // bytes that won't match the stored hash.
    let bogus_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let header = format!("Bearer lk_{pid}.{bogus_secret}");
    let err = f
        .bearer
        .authenticate_bearer(&header)
        .await
        .expect_err("wrong secret");
    let _ = err;

    let rows = f
        .audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.event, "auth_failure");
    // We don't leak the agent_public_id on auth_failure — the wire shape
    // is deliberately uniform per §4.7.9 / Q-8 — but ops still need to
    // correlate, so the public_id IS recorded in the audit row.
    assert_eq!(row.agent_public_id.as_deref(), Some(pid.as_str()));
}

#[tokio::test]
async fn operator_unknown_token_emits_security_audit_row() {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let audit = AuditRepository::new(pool);
    // operators.yaml with one operator we won't use.
    let real = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let real_hash = argon2_helper::hash(&secrecy::SecretString::from(
        real.secret.expose().to_string(),
    ))
    .unwrap();
    let ops_path = dir.path().join("operators.yaml");
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            real.public_id.as_str(),
            real_hash
        ),
    )
    .unwrap();
    let op_auth = OperatorAuthenticator::load_with_audit(&ops_path, Some(audit.clone())).unwrap();

    // Present a token whose public_id doesn't exist.
    let bogus = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let err = op_auth
        .authenticate_bearer(&format!("Bearer {}", bogus.wire_format()))
        .await
        .expect_err("unknown operator id");
    let _ = err;

    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_class, EventClass::Security);
    assert_eq!(rows[0].event, "operator_auth_failure");
}

#[tokio::test]
async fn bootstrap_reuse_emits_security_audit_row() {
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
    let admin = AdminService::with_audit(
        agents,
        bootstrap,
        Arc::new(ArcSwap::from_pointee(cfg)),
        Some(audit.clone()),
    );

    let op = agent_locksmith::auth_v2::OperatorIdentity {
        name: "alice".into(),
        scope: None,
        auth_method: None,
    };
    // Mint single-use bootstrap.
    let minted = admin
        .mint_bootstrap_token(
            &op,
            MintBootstrapInput {
                tool_allowlist: None,
                expires_at: None,
                single_use: true,
            },
        )
        .await
        .unwrap();
    // First register: succeeds.
    admin
        .register_agent(RegisterInput {
            bootstrap_token: SecretString::from(minted.token.clone()),
            name: "agent-1".into(),
            description: None,
            metadata: None,
        })
        .await
        .unwrap();
    // Second register with same token: must fail as InvalidBootstrap.
    let err = admin
        .register_agent(RegisterInput {
            bootstrap_token: SecretString::from(minted.token.clone()),
            name: "agent-2".into(),
            description: None,
            metadata: None,
        })
        .await
        .expect_err("reuse rejected");
    let _ = err;

    // Among the rows there must be a security-class bootstrap_reuse_attempt.
    let rows = audit
        .query(
            &AuditFilter {
                event_class: Some(EventClass::Security),
                ..AuditFilter::default()
            },
            AuditPage::default(),
        )
        .await
        .unwrap();
    let reuse = rows.iter().find(|r| r.event == "bootstrap_reuse_attempt");
    let row = reuse.expect("bootstrap_reuse_attempt row exists");
    assert_eq!(row.decision, Decision::Denied);
    assert_eq!(
        row.details
            .as_ref()
            .and_then(|d| d.get("bootstrap_public_id"))
            .and_then(|v| v.as_str()),
        Some(minted.public_id.as_str())
    );
}
