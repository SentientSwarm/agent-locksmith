//! SQLite pool + migration runner (T2.3 / C-19).
//!
//! Opens the SQLite database at the configured path with INF-21 PRAGMAs
//! applied at every pooled connection (sqlx does not persist PRAGMAs
//! across connections, so the after-connect hook re-applies the
//! per-connection ones). Then runs all checked-in migrations from
//! `migrations/`. Forward-only by design (INF-11).

use sqlx::ConnectOptions;
use sqlx::Executor;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Open a SQLite pool at `path` (creating the file if missing) with the
/// INF-21 PRAGMAs applied, run all pending migrations, and return the
/// pool ready for the application to use.
pub async fn open_and_migrate(path: &Path) -> Result<SqlitePool, MigrationError> {
    // SqliteConnectOptions controls the per-connection settings sqlx can
    // express directly: journal mode, synchronous, foreign keys, busy
    // timeout. `wal_autocheckpoint` is set via the after-connect hook
    // (sqlx does not expose it as a typed option).
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_millis(5000))
        // Disable sqlx statement logging for the auth path's hot lookups.
        .disable_statement_logging();

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                // Knobs that SqliteConnectOptions does not surface as
                // typed settings. INF-21.
                conn.execute("PRAGMA wal_autocheckpoint = 1000;").await?;
                Ok(())
            })
        })
        .connect_with(opts)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
