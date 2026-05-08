//! T3.5 — Audit retention sweeper. 90-day time-based delete (Q-26 C).
//!
//! Verification gate: sweep affects only the audit table; arithmetic
//! uses unix-ms consistently; idempotent; observes shutdown.

use agent_locksmith::config::parse_config_str;
use agent_locksmith::migrations::open_and_migrate;
use agent_locksmith::repo::AgentRepository;
use agent_locksmith::repo::audit::{
    AuditEvent, AuditFilter, AuditPage, AuditRepository, Decision, EventClass,
};
use std::time::Duration;
use tempfile::TempDir;

const MS_PER_DAY: i64 = 24 * 60 * 60 * 1_000;

async fn fixture() -> (TempDir, AuditRepository, AgentRepository) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let audit = AuditRepository::new(pool.clone());
    let agents = AgentRepository::new(pool);
    (dir, audit, agents)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn event_at(ts_ms: i64, event: &str) -> AuditEvent {
    AuditEvent {
        ts_ms,
        event_class: EventClass::Operator,
        event: event.into(),
        decision: Decision::Allowed,
        ..AuditEvent::default()
    }
}

#[tokio::test]
async fn sweep_deletes_rows_older_than_cutoff() {
    let (_d, audit, _agents) = fixture().await;
    let now = now_ms();
    let old = now - 100 * MS_PER_DAY;
    let recent = now - 5 * MS_PER_DAY;
    audit.record(&event_at(old, "old")).await.unwrap();
    audit.record(&event_at(recent, "recent")).await.unwrap();

    let cutoff = now - 90 * MS_PER_DAY;
    let deleted = audit.sweep_older_than(cutoff).await.unwrap();
    assert_eq!(deleted, 1, "exactly the old row is deleted");

    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event, "recent");
}

#[tokio::test]
async fn sweep_is_idempotent() {
    let (_d, audit, _agents) = fixture().await;
    let now = now_ms();
    audit
        .record(&event_at(now - 100 * MS_PER_DAY, "old"))
        .await
        .unwrap();
    let cutoff = now - 90 * MS_PER_DAY;
    assert_eq!(audit.sweep_older_than(cutoff).await.unwrap(), 1);
    assert_eq!(
        audit.sweep_older_than(cutoff).await.unwrap(),
        0,
        "second sweep is a no-op"
    );
}

#[tokio::test]
async fn sweep_does_not_touch_other_tables() {
    let (_d, audit, agents) = fixture().await;
    // Create one agent + one ancient audit row.
    let (pid, _) = agents
        .create("a-1", None, None, None, None, None)
        .await
        .unwrap();
    let now = now_ms();
    audit
        .record(&event_at(now - 365 * MS_PER_DAY, "ancient"))
        .await
        .unwrap();
    audit.sweep_older_than(now).await.unwrap();
    // Agent must still exist.
    let still_there = agents.get_active_by_public_id(&pid).await.unwrap();
    assert!(still_there.is_some(), "sweep must not affect agents table");
}

#[tokio::test]
async fn sweep_with_no_old_rows_returns_zero() {
    let (_d, audit, _agents) = fixture().await;
    let now = now_ms();
    audit.record(&event_at(now, "fresh")).await.unwrap();
    let cutoff = now - 90 * MS_PER_DAY;
    assert_eq!(audit.sweep_older_than(cutoff).await.unwrap(), 0);
    let rows = audit
        .query(&AuditFilter::default(), AuditPage::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "fresh row preserved");
}

#[tokio::test]
async fn config_audit_retention_fields_parse() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
audit:
  retention_days: 30
  sweep_interval_seconds: 600
tools: []
"#;
    let cfg = parse_config_str(yaml).expect("parses");
    let audit = cfg.audit.expect("audit block present");
    assert_eq!(audit.retention_days, 30);
    assert_eq!(audit.sweep_interval_seconds, 600);
}

#[tokio::test]
async fn config_audit_defaults_when_absent() {
    let yaml = r#"
listen:
  host: "127.0.0.1"
  port: 9200
tools: []
"#;
    let cfg = parse_config_str(yaml).expect("parses");
    // The block is optional; the daemon applies defaults at runtime
    // (90 days / 3600 seconds) when constructing the sweeper.
    assert!(cfg.audit.is_none());
}

#[tokio::test]
async fn daemon_spawns_sweeper_when_admin_substrate_enabled() {
    use agent_locksmith::{argon2_helper, daemon, token};

    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("admin.sock");
    let ops = dir.path().join("operators.yaml");
    let db = dir.path().join("locksmith.db");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let op_tok = token::StructuredToken::generate(token::TokenNamespace::Operator);
    std::fs::write(
        &ops,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_tok.public_id.as_str(),
            argon2_helper::hash(&secrecy::SecretString::from(
                op_tok.secret.expose().to_string()
            ))
            .unwrap()
        ),
    )
    .unwrap();

    // Aggressive sweep cadence for the test; retention = 0 means anything
    // older than now-0ms gets swept (i.e. all rows older than "now").
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {port}
  admin_socket:
    path: "{sock}"
operator_credentials_path: "{ops}"
database:
  path: "{db}"
audit:
  retention_days: 0
  sweep_interval_seconds: 1
tools: []
"#,
        sock = socket.display(),
        ops = ops.display(),
        db = db.display(),
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;

    // Wait for socket to come up — the sweeper has spawned by then.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !socket.exists() {
        if std::time::Instant::now() > deadline {
            panic!("socket not bound");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Insert a row dated 1 day ago. With retention_days=0 + 1s cadence,
    // the sweeper should delete it within ~2s.
    let pool = agent_locksmith::migrations::open_and_migrate(&db)
        .await
        .unwrap();
    let audit = AuditRepository::new(pool);
    audit
        .record(&event_at(now_ms() - MS_PER_DAY, "to-be-swept"))
        .await
        .unwrap();

    // Wait up to 5s for the sweeper to drop the row.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let rows = audit
            .query(&AuditFilter::default(), AuditPage::default())
            .await
            .unwrap();
        // Any 'to-be-swept' row should be gone.
        if !rows.iter().any(|r| r.event == "to-be-swept") {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("sweeper did not delete the old row within 5s");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    coord.trigger();
    let _ = tokio::time::timeout(Duration::from_secs(6), handle).await;
}
