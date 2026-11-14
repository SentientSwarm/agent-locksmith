//! Offline re-key of `credential_secrets` (ADR-0008 D2).
//!
//! Unseals every stored value with the old credential sealing key and
//! reseals it under the new one with a fresh nonce, in one transaction.
//! Any value the old key cannot open aborts the whole run, so a wrong
//! key changes nothing. Plaintext lives only in a zeroizing buffer for
//! the duration of one row.
//!
//! Gives the store a key-rotation path and lets a database copy (for
//! example a staging refresh) get its own key without sharing prod's.
//! The daemon reads `credential_secrets` per request, so run this with
//! the daemon stopped. The write lock is taken up front (`BEGIN
//! IMMEDIATE`), and on success the WAL is checkpointed into the database
//! file and the connection closed, so the result is entirely in the `.db`
//! file before the process exits.
//!
//! Re-keying changes only the key: a copy of a database keeps every stored
//! value it had, and its OAuth rows stay sealed under the OAuth key.

use std::path::Path;
use std::time::Duration;

use secrecy::zeroize::Zeroizing;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, Connection, SqliteConnection};

use super::CredentialSealingKey;

#[derive(Debug, thiserror::Error)]
pub enum RekeyError {
    /// The old key does not open a stored value. Nothing was changed.
    #[error("the old credential sealing key does not open the stored values")]
    WrongKey,
    #[error("sealing under the new key failed")]
    Seal,
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
}

/// Re-key every row of `credential_secrets`, tombstoned rows included.
/// Returns the number of rows rewritten.
pub async fn rekey_credentials(
    db: &Path,
    old: &CredentialSealingKey,
    new: &CredentialSealingKey,
) -> Result<usize, RekeyError> {
    let options = SqliteConnectOptions::new()
        .filename(db)
        .create_if_missing(false)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        .disable_statement_logging();
    let mut conn = SqliteConnection::connect_with(&options).await?;
    let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
    let rows: Vec<(String, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT secret_ref, sealed_value, nonce FROM credential_secrets")
            .fetch_all(&mut *tx)
            .await?;
    for (secret_ref, sealed, nonce) in &rows {
        let plain = Zeroizing::new(
            old.unseal(sealed, nonce)
                .map_err(|_| RekeyError::WrongKey)?,
        );
        let (ct, fresh) = new.seal(&plain).map_err(|_| RekeyError::Seal)?;
        sqlx::query(
            "UPDATE credential_secrets SET sealed_value = ?, nonce = ? WHERE secret_ref = ?",
        )
        .bind(ct)
        .bind(fresh)
        .bind(secret_ref)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&mut conn)
        .await?;
    conn.close().await?;
    Ok(rows.len())
}
