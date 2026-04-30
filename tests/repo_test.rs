//! Repository integration tests (T2.5/T2.6/T2.7).
//! Covers INF-9 (rotate), INF-10 (concurrent register), R-F11 (bootstrap).

use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::{
    AgentRepository, AuditEvent, AuditFilter, AuditPage, AuditRepository, BootstrapScope,
    BootstrapTokenRepository, Decision, EventClass, RepoError,
};
use secrecy::SecretString;
use sqlx::SqlitePool;
use tempfile::TempDir;

async fn fresh_pool() -> (TempDir, SqlitePool) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    (dir, pool)
}

// ─── AgentRepository ───────────────────────────────────────────────

#[tokio::test]
async fn agent_create_and_lookup_by_public_id() {
    let (_dir, pool) = fresh_pool().await;
    let repo = AgentRepository::new(pool);
    let (pid, _secret) = repo
        .create("agent-7", Some("desc"), None, None, None, None)
        .await
        .unwrap();
    let got = repo.get_active_by_public_id(&pid).await.unwrap();
    assert!(got.is_some());
    let rec = got.unwrap();
    assert_eq!(rec.name, "agent-7");
    assert_eq!(rec.public_id, pid);
    assert!(rec.is_active());
}

#[tokio::test]
async fn agent_create_rejects_duplicate_name() {
    let (_dir, pool) = fresh_pool().await;
    let repo = AgentRepository::new(pool);
    repo.create("dup", None, None, None, None, None)
        .await
        .unwrap();
    let res = repo.create("dup", None, None, None, None, None).await;
    assert!(matches!(res, Err(RepoError::AgentNameConflict(ref n)) if n == "dup"));
}

#[tokio::test]
async fn agent_concurrent_create_same_name_one_succeeds() {
    // INF-10: two concurrent inserts → one success + one
    // AgentNameConflict; bootstrap NOT consumed for failed call (the
    // bootstrap consume happens in AdminService, not the repo).
    let (_dir, pool) = fresh_pool().await;
    let repo = std::sync::Arc::new(AgentRepository::new(pool));
    let r1 = repo.clone();
    let r2 = repo.clone();
    let h1 = tokio::spawn(async move { r1.create("racey", None, None, None, None, None).await });
    let h2 = tokio::spawn(async move { r2.create("racey", None, None, None, None, None).await });
    let (a, b) = tokio::join!(h1, h2);
    let a = a.unwrap();
    let b = b.unwrap();
    let oks = [a.is_ok(), b.is_ok()].iter().filter(|x| **x).count();
    let conflicts = [a.is_err(), b.is_err()].iter().filter(|x| **x).count();
    assert_eq!(oks, 1, "exactly one create should succeed");
    assert_eq!(conflicts, 1, "exactly one create should conflict");
}

#[tokio::test]
async fn agent_revoke_excludes_from_active_lookup() {
    let (_dir, pool) = fresh_pool().await;
    let repo = AgentRepository::new(pool);
    let (pid, _) = repo
        .create("a", None, None, None, None, None)
        .await
        .unwrap();
    repo.revoke(&pid).await.unwrap();
    assert!(repo.get_active_by_public_id(&pid).await.unwrap().is_none());
}

#[tokio::test]
async fn agent_rotate_issues_new_secret_and_invalidates_old() {
    let (_dir, pool) = fresh_pool().await;
    let repo = AgentRepository::new(pool);
    let (pid, secret_v1) = repo
        .create("rotater", None, None, None, None, None)
        .await
        .unwrap();
    let secret_v2 = repo.rotate(&pid, &secret_v1).await.unwrap();
    // Old secret no longer rotates
    let res = repo.rotate(&pid, &secret_v1).await;
    assert!(matches!(res, Err(RepoError::InvalidCredential)));
    // New secret does
    let _v3 = repo.rotate(&pid, &secret_v2).await.unwrap();
}

#[tokio::test]
async fn agent_concurrent_rotate_one_wins() {
    // INF-9: two concurrent rotate calls → exactly-one-success.
    let (_dir, pool) = fresh_pool().await;
    let repo = std::sync::Arc::new(AgentRepository::new(pool));
    let (pid, secret) = repo
        .create("racey-rot", None, None, None, None, None)
        .await
        .unwrap();
    let r1 = repo.clone();
    let r2 = repo.clone();
    let pid1 = pid.clone();
    let pid2 = pid.clone();
    let s1 = SecretString::from(secrecy::ExposeSecret::expose_secret(&secret).to_string());
    let s2 = SecretString::from(secrecy::ExposeSecret::expose_secret(&secret).to_string());
    let h1 = tokio::spawn(async move { r1.rotate(&pid1, &s1).await });
    let h2 = tokio::spawn(async move { r2.rotate(&pid2, &s2).await });
    let (a, b) = tokio::join!(h1, h2);
    let a = a.unwrap();
    let b = b.unwrap();
    let oks = [a.is_ok(), b.is_ok()].iter().filter(|x| **x).count();
    let conflicts = [
        matches!(
            a,
            Err(RepoError::RotationInProgress(_)) | Err(RepoError::InvalidCredential)
        ),
        matches!(
            b,
            Err(RepoError::RotationInProgress(_)) | Err(RepoError::InvalidCredential)
        ),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    assert_eq!(oks, 1, "exactly one rotate should succeed");
    assert_eq!(
        conflicts, 1,
        "the other must be RotationInProgress or InvalidCredential"
    );
}

// ─── BootstrapTokenRepository ──────────────────────────────────────

#[tokio::test]
async fn bootstrap_mint_and_consume_single_use() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool.clone());
    let boots = BootstrapTokenRepository::new(pool);
    let scope = BootstrapScope {
        tool_allowlist: Some(vec!["github".into()]),
        expires_at: None,
        single_use: true,
    };
    let (pid, secret) = boots.mint(scope, "alice").await.unwrap();
    let (agent_pid, _) = agents
        .create("a", None, None, None, None, None)
        .await
        .unwrap();
    let agent = agents
        .get_active_by_public_id(&agent_pid)
        .await
        .unwrap()
        .unwrap();
    let consumed_scope = boots.consume(&pid, &secret, agent.id).await.unwrap();
    assert_eq!(consumed_scope.tool_allowlist.unwrap()[0], "github");
    // Second consume → InvalidCredential (R-F11; INF-13 reuse-attempt
    // flagging is the AdminService's responsibility).
    let res = boots.consume(&pid, &secret, agent.id).await;
    assert!(matches!(res, Err(RepoError::InvalidCredential)));
}

#[tokio::test]
async fn bootstrap_concurrent_consume_one_wins() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool.clone());
    let boots = std::sync::Arc::new(BootstrapTokenRepository::new(pool));
    let scope = BootstrapScope {
        tool_allowlist: None,
        expires_at: None,
        single_use: true,
    };
    let (pid, secret) = boots.mint(scope, "alice").await.unwrap();
    let (agent_pid, _) = agents
        .create("a", None, None, None, None, None)
        .await
        .unwrap();
    let agent = agents
        .get_active_by_public_id(&agent_pid)
        .await
        .unwrap()
        .unwrap();
    let b1 = boots.clone();
    let b2 = boots.clone();
    let pid1 = pid.clone();
    let pid2 = pid.clone();
    let s1 = SecretString::from(secrecy::ExposeSecret::expose_secret(&secret).to_string());
    let s2 = SecretString::from(secrecy::ExposeSecret::expose_secret(&secret).to_string());
    let aid = agent.id;
    let h1 = tokio::spawn(async move { b1.consume(&pid1, &s1, aid).await });
    let h2 = tokio::spawn(async move { b2.consume(&pid2, &s2, aid).await });
    let (a, b) = tokio::join!(h1, h2);
    let a = a.unwrap();
    let b = b.unwrap();
    let oks = [a.is_ok(), b.is_ok()].iter().filter(|x| **x).count();
    assert_eq!(oks, 1, "exactly one consume should succeed");
}

#[tokio::test]
async fn bootstrap_expired_token_rejected() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool.clone());
    let boots = BootstrapTokenRepository::new(pool);
    let scope = BootstrapScope {
        tool_allowlist: None,
        expires_at: Some(0), // 1970-01-01: long expired
        single_use: true,
    };
    let (pid, secret) = boots.mint(scope, "alice").await.unwrap();
    let (apid, _) = agents
        .create("a", None, None, None, None, None)
        .await
        .unwrap();
    let agent = agents
        .get_active_by_public_id(&apid)
        .await
        .unwrap()
        .unwrap();
    let res = boots.consume(&pid, &secret, agent.id).await;
    assert!(matches!(res, Err(RepoError::InvalidCredential)));
}

// ─── AuditRepository ───────────────────────────────────────────────

#[tokio::test]
async fn audit_record_and_query_roundtrip() {
    let (_dir, pool) = fresh_pool().await;
    let audit = AuditRepository::new(pool);
    let event = AuditEvent {
        ts_ms: 1000,
        event_class: EventClass::Proxy,
        event: "proxy_request".to_string(),
        agent_public_id: Some("ag_test".to_string()),
        tool: Some("github".to_string()),
        decision: Decision::Allowed,
        ..Default::default()
    };
    audit.record(&event).await.unwrap();

    let results = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event, "proxy_request");
    assert_eq!(results[0].agent_public_id.as_deref(), Some("ag_test"));
}

#[tokio::test]
async fn audit_filter_by_tool_and_class() {
    let (_dir, pool) = fresh_pool().await;
    let audit = AuditRepository::new(pool);
    for (event, tool, class) in [
        ("a", "github", EventClass::Proxy),
        ("b", "anthropic", EventClass::Proxy),
        ("c", "github", EventClass::Operator),
    ] {
        audit
            .record(&AuditEvent {
                ts_ms: 1,
                event_class: class,
                event: event.to_string(),
                tool: Some(tool.to_string()),
                decision: Decision::Allowed,
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let filter = AuditFilter {
        tool: Some("github".to_string()),
        ..Default::default()
    };
    let results = audit.query(&filter, AuditPage::default()).await.unwrap();
    assert_eq!(results.len(), 2);

    let filter = AuditFilter {
        event_class: Some(EventClass::Proxy),
        ..Default::default()
    };
    let results = audit.query(&filter, AuditPage::default()).await.unwrap();
    assert_eq!(results.len(), 2);
}
