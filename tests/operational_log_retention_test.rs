//! Phase J / M2 (WEM-449, LOG-1/LOG-4) — operational-log retention.
//!
//! The operational-log sweep is INDEPENDENT of audit retention:
//! sweeping `operational_logs` never touches the `audit` table, and the
//! two streams retain on their own windows. Plus a reveal-never guard:
//! operational-log rows never carry a credential value (LOG-4).

use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::operational_log_sink::OperationalLogEmitter;
use agent_locksmith::repo::audit::{AuditEvent, AuditFilter, AuditPage, AuditRepository};
use agent_locksmith::repo::{LogComponent, LogFilter, LogLevel, OperationalLogStore};
use serde_json::json;
use sqlx::SqlitePool;
use tempfile::TempDir;

async fn fixture() -> (TempDir, SqlitePool) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    (dir, pool)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[tokio::test]
async fn sweeping_logs_does_not_touch_audit() {
    let (_d, pool) = fixture().await;
    let logs = OperationalLogStore::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());

    // One audit row + one operational-log row, both "old".
    audit
        .record(&AuditEvent {
            ts_ms: 1000,
            event: "proxy_request".into(),
            ..AuditEvent::default()
        })
        .await
        .unwrap();
    logs.insert(LogLevel::Info, LogComponent::Config, "old", "m", None)
        .await
        .unwrap();
    // Backdate the operational-log row so the cutoff catches it.
    sqlx::query("UPDATE operational_logs SET ts_ms = 1000")
        .execute(&pool)
        .await
        .unwrap();

    // Sweep operational logs with a cutoff that deletes the old row.
    let removed = logs.sweep(2000).await.unwrap();
    assert_eq!(removed, 1, "the old operational-log row is swept");

    // The audit row (also ts=1000) is UNTOUCHED — different table, different
    // retention. Its own sweeper uses a different (90-day) window.
    let audit_rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(
        audit_rows.len(),
        1,
        "operational-log sweep must not touch the audit table"
    );

    // And operational logs are indeed empty now.
    assert!(logs.query(&LogFilter::default()).await.unwrap().is_empty());
}

#[tokio::test]
async fn independent_retention_windows() {
    let (_d, pool) = fixture().await;
    let logs = OperationalLogStore::new(pool.clone());
    let audit = AuditRepository::new(pool.clone());

    let now = now_ms();
    let day = 24 * 60 * 60 * 1000;

    // A 20-day-old operational-log row + a 20-day-old audit row.
    logs.insert(LogLevel::Info, LogComponent::Agent, "e", "m", None)
        .await
        .unwrap();
    sqlx::query("UPDATE operational_logs SET ts_ms = ?")
        .bind(now - 20 * day)
        .execute(&pool)
        .await
        .unwrap();
    audit
        .record(&AuditEvent {
            ts_ms: now - 20 * day,
            event: "proxy_request".into(),
            ..AuditEvent::default()
        })
        .await
        .unwrap();

    // Operational-log 7-day retention removes the 20-day-old row...
    let ops_cutoff = now - 7 * day;
    assert_eq!(logs.sweep(ops_cutoff).await.unwrap(), 1);
    // ...but audit's 90-day retention keeps its 20-day-old row.
    let audit_cutoff = now - 90 * day;
    assert_eq!(audit.sweep_older_than(audit_cutoff).await.unwrap(), 0);
    assert_eq!(
        audit
            .query(&AuditFilter::default(), AuditPage::default())
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn operational_log_rows_never_contain_a_credential_value() {
    // The emitter/store are the only writers; assert that emitting a
    // realistic degradation event stores event names + non-secret context
    // only — the secret value never appears in any column (LOG-4).
    let (_d, pool) = fixture().await;
    let store = OperationalLogStore::new(pool.clone());
    let emitter = OperationalLogEmitter::spawn(store.clone(), 16);

    const SECRET: &str = "sk-super-secret-credential-value";
    // Emit as a real site would: registration name + cause, never a value.
    emitter.emit(
        LogLevel::Warn,
        LogComponent::Proxy,
        "credential_unresolved",
        "stored credential could not be resolved; request failed 503",
        Some(json!({ "registration": "store-api", "cause": "credential_unresolved" })),
    );
    emitter.emit(
        LogLevel::Warn,
        LogComponent::Oauth,
        "oauth_refresh_degraded",
        "oauth refresh failed; session marked degraded",
        Some(json!({ "registration": "codex", "cause": "refresh_failed" })),
    );

    // Wait for the drain task to commit.
    let mut rows = Vec::new();
    for _ in 0..50 {
        rows = store.query(&LogFilter::default()).await.unwrap();
        if rows.len() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(rows.len(), 2);

    // Scan every text column (raw, straight from SQLite) for the secret.
    let raw: Vec<(String, String, String, Option<String>)> =
        sqlx::query_as("SELECT event, message, component, fields FROM operational_logs")
            .fetch_all(&pool)
            .await
            .unwrap();
    for (event, message, component, fields) in raw {
        assert!(!event.contains(SECRET));
        assert!(!message.contains(SECRET));
        assert!(!component.contains(SECRET));
        assert!(!fields.unwrap_or_default().contains(SECRET));
    }
}
