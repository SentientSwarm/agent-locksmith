//! T2.9 / T2.10 — AgentAuthenticator + OperatorAuthenticator integration.

use agent_locksmith::auth_v2::{
    AgentAuthenticator, AuthError, BearerAuthenticator, OperatorAuthenticator,
};
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::{argon2_helper, token};
use secrecy::{ExposeSecret, SecretString};
use sqlx::SqlitePool;
use tempfile::TempDir;

async fn fresh_pool() -> (TempDir, SqlitePool) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    (dir, pool)
}

// ─── AgentAuthenticator (T2.9) ─────────────────────────────────────

#[tokio::test]
async fn agent_bearer_accepts_valid_token() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool);
    let (pid, secret) = agents
        .create("agent-1", None, None, None, None, None)
        .await
        .unwrap();
    let auth = BearerAuthenticator::new(agents).unwrap();

    let header = format!("Bearer lk_{pid}.{}", secret.expose_secret());
    let identity = auth.authenticate_bearer(&header).await.unwrap();
    assert_eq!(identity.public_id, pid);
    assert_eq!(identity.name, "agent-1");
}

#[tokio::test]
async fn agent_bearer_rejects_unknown_public_id() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool);
    let auth = BearerAuthenticator::new(agents).unwrap();
    // Generate a well-formed but never-stored token.
    let t = token::StructuredToken::generate(token::TokenNamespace::Agent);
    let header = format!("Bearer {}", t.wire_format());
    let res = auth.authenticate_bearer(&header).await;
    assert!(matches!(res, Err(AuthError::InvalidCredential)));
}

#[tokio::test]
async fn agent_bearer_rejects_wrong_secret() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool);
    let (pid, _real_secret) = agents
        .create("agent-2", None, None, None, None, None)
        .await
        .unwrap();
    let auth = BearerAuthenticator::new(agents).unwrap();

    // Generate a valid public_id format but wrong secret.
    let bogus = token::StructuredToken::generate(token::TokenNamespace::Agent);
    let header = format!("Bearer lk_{pid}.{}", bogus.secret.expose());
    let res = auth.authenticate_bearer(&header).await;
    assert!(matches!(res, Err(AuthError::InvalidCredential)));
}

#[tokio::test]
async fn agent_bearer_rejects_revoked_agent() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool);
    let (pid, secret) = agents
        .create("agent-3", None, None, None, None, None)
        .await
        .unwrap();
    agents.revoke(&pid).await.unwrap();
    let auth = BearerAuthenticator::new(agents).unwrap();

    // get_active_by_public_id excludes revoked → InvalidCredential
    // (not Revoked, which would distinguish revoked from "no such agent"
    // and leak existence information).
    let header = format!("Bearer lk_{pid}.{}", secret.expose_secret());
    let res = auth.authenticate_bearer(&header).await;
    assert!(matches!(res, Err(AuthError::InvalidCredential)));
}

#[tokio::test]
async fn agent_bearer_missing_authorization_header() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool);
    let auth = BearerAuthenticator::new(agents).unwrap();
    let res = auth.authenticate_bearer("NotBearer something").await;
    assert!(matches!(res, Err(AuthError::MissingCredential)));
}

#[tokio::test]
async fn agent_bearer_rejects_malformed_token() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool);
    let auth = BearerAuthenticator::new(agents).unwrap();
    let res = auth.authenticate_bearer("Bearer lk_short.x").await;
    assert!(matches!(res, Err(AuthError::InvalidCredential)));
}

#[tokio::test]
async fn agent_bearer_rejects_wrong_namespace_prefix() {
    // Operator-namespace token (lkop_) should NOT authenticate as an agent.
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool);
    let auth = BearerAuthenticator::new(agents).unwrap();
    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let header = format!("Bearer {}", op_token.wire_format());
    let res = auth.authenticate_bearer(&header).await;
    assert!(matches!(res, Err(AuthError::InvalidCredential)));
}

#[tokio::test]
async fn agent_bearer_touches_last_used() {
    let (_dir, pool) = fresh_pool().await;
    let agents = AgentRepository::new(pool);
    let (pid, secret) = agents
        .create("agent-4", None, None, None, None, None)
        .await
        .unwrap();
    let auth = BearerAuthenticator::new(agents.clone()).unwrap();

    // Pre-auth: last_used_at is None.
    let pre = agents.get_active_by_public_id(&pid).await.unwrap().unwrap();
    assert!(pre.last_used_at.is_none());

    let header = format!("Bearer lk_{pid}.{}", secret.expose_secret());
    auth.authenticate_bearer(&header).await.unwrap();

    let post = agents.get_active_by_public_id(&pid).await.unwrap().unwrap();
    assert!(
        post.last_used_at.is_some(),
        "auth should touch last_used_at"
    );
}

// ─── OperatorAuthenticator (T2.10) ─────────────────────────────────

#[tokio::test]
async fn operator_bearer_accepts_valid_token() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("operators.yaml");

    // Create an operator record with a known secret.
    let op_token = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let secret_str = SecretString::from(op_token.secret.expose().to_string());
    let token_hash = argon2_helper::hash(&secret_str).unwrap();

    let yaml = format!(
        "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
        op_token.public_id.as_str(),
        token_hash
    );
    std::fs::write(&path, yaml).unwrap();

    let auth = OperatorAuthenticator::load(&path).unwrap();
    let header = format!("Bearer {}", op_token.wire_format());
    let identity = auth.authenticate_bearer(&header).await.unwrap();
    assert_eq!(identity.name, "alice");
}

#[tokio::test]
async fn operator_bearer_rejects_unknown_operator() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("operators.yaml");
    std::fs::write(&path, "operators: []\n").unwrap();
    let auth = OperatorAuthenticator::load(&path).unwrap();
    let stranger = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let header = format!("Bearer {}", stranger.wire_format());
    let res = auth.authenticate_bearer(&header).await;
    assert!(matches!(res, Err(AuthError::InvalidCredential)));
}

#[tokio::test]
async fn operator_loader_fails_fast_on_missing_file() {
    let dir = TempDir::new().unwrap();
    let bogus = dir.path().join("does-not-exist.yaml");
    let res = OperatorAuthenticator::load(&bogus);
    assert!(matches!(res, Err(AuthError::Backend(_))));
}

#[tokio::test]
async fn operator_bearer_rejects_agent_namespace_token() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("operators.yaml");
    std::fs::write(&path, "operators: []\n").unwrap();
    let auth = OperatorAuthenticator::load(&path).unwrap();

    let agent_token = token::StructuredToken::generate(token::TokenNamespace::Agent);
    let header = format!("Bearer {}", agent_token.wire_format());
    let res = auth.authenticate_bearer(&header).await;
    assert!(matches!(res, Err(AuthError::InvalidCredential)));
}
