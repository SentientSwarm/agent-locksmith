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
//! the daemon stopped.

use std::path::Path;
use std::time::Duration;

use secrecy::zeroize::Zeroizing;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, SqliteConnection};

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
        .busy_timeout(Duration::from_secs(5));
    let mut conn = SqliteConnection::connect_with(&options).await?;
    let mut tx = conn.begin().await?;
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
    Ok(rows.len())
}
