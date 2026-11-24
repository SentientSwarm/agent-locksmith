//! The schema version an upgrade must reach (AGENT-348).
//!
//! Every upgrade test compares against `latest()`, so a new migration is
//! one edit here instead of one per test. The value is kept by hand, not
//! read from `migrations/`, so it stays an independent expectation:
//! `embedded_migrations_are_one_to_latest` fails in a plain `cargo test`
//! when a migration is added, removed or renumbered without updating it.

/// The highest migration version the current daemon must apply.
const LATEST: i64 = 28;

pub fn latest() -> i64 {
    LATEST
}

#[test]
fn embedded_migrations_are_one_to_latest() {
    let versions: Vec<i64> = sqlx::migrate!("./migrations")
        .iter()
        .map(|m| m.version)
        .collect();
    assert_eq!(
        versions,
        (1..=LATEST).collect::<Vec<_>>(),
        "migrations/ changed: update LATEST in tests/support/latest_migration.rs \
         (every upgrade test expects it) and check the upgrade tests still hold"
    );
}
