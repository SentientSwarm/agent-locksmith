//! T2.3 — MigrationRunner integration tests.
//! Covers: R-F8, R-N1, INF-11, INF-21, Q-5, Q-16.

use agent_locksmith::migrations::open_and_migrate;
use sqlx::Row;
use tempfile::TempDir;

async fn fresh_db() -> (TempDir, sqlx::SqlitePool) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("locksmith.db");
    let pool = open_and_migrate(&path).await.expect("first migrate");
    (dir, pool)
}

#[tokio::test]
async fn migrations_apply_on_fresh_db() {
    let (_dir, pool) = fresh_db().await;
    // Schema present: agents, bootstrap_tokens, audit
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' \
         AND name IN ('agents','bootstrap_tokens','audit')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, 3, "expected three M2 tables");
}

#[tokio::test]
async fn migrations_are_idempotent() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("locksmith.db");
    let _pool1 = open_and_migrate(&path).await.expect("first migrate");
    // Re-running on an already-migrated db should be a no-op (sqlx tracks
    // applied migrations in `_sqlx_migrations`).
    let _pool2 = open_and_migrate(&path).await.expect("re-run is idempotent");
}

#[tokio::test]
async fn wal_mode_is_active_on_pool_connections() {
    let (_dir, pool) = fresh_db().await;
    let row = sqlx::query("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mode: String = row.get(0);
    assert_eq!(mode.to_lowercase(), "wal");
}

#[tokio::test]
async fn foreign_keys_enabled() {
    let (_dir, pool) = fresh_db().await;
    let row = sqlx::query("PRAGMA foreign_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    let enabled: i64 = row.get(0);
    assert_eq!(enabled, 1);
}

#[tokio::test]
async fn check_constraint_rejects_invalid_event_class() {
    let (_dir, pool) = fresh_db().await;
    let res = sqlx::query(
        "INSERT INTO audit (ts, event_class, event, decision) \
         VALUES (1, 'invalid', 'test', 'allowed')",
    )
    .execute(&pool)
    .await;
    assert!(
        res.is_err(),
        "CHECK constraint must reject 'invalid' event_class"
    );
}

#[tokio::test]
async fn check_constraint_rejects_invalid_decision() {
    let (_dir, pool) = fresh_db().await;
    let res = sqlx::query(
        "INSERT INTO audit (ts, event_class, event, decision) \
         VALUES (1, 'proxy', 'test', 'maybe')",
    )
    .execute(&pool)
    .await;
    assert!(
        res.is_err(),
        "CHECK constraint must reject 'maybe' decision"
    );
}

#[tokio::test]
async fn agents_unique_name_enforced() {
    let (_dir, pool) = fresh_db().await;
    sqlx::query(
        "INSERT INTO agents (public_id, name, secret_hash, registered_at) \
         VALUES ('p1', 'agent-a', 'h', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let res = sqlx::query(
        "INSERT INTO agents (public_id, name, secret_hash, registered_at) \
         VALUES ('p2', 'agent-a', 'h', 2)",
    )
    .execute(&pool)
    .await;
    assert!(
        res.is_err(),
        "UNIQUE(name) must reject duplicate agent name"
    );
}
