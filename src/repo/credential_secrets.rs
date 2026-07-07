//! `credential_secrets` repository — Phase J (ADR-0008).
//!
//! Sealed at-rest storage of stored-credential **values** for the
//! `stored` custody backend. Each row holds AES-GCM ciphertext + its
//! per-row 12-byte nonce, sealed by [`crate::secret::CredentialSealingKey`]
//! (T1.1) with the independent `LOCKSMITH_CREDENTIAL_SEALING_KEY`. The
//! `stored_*` AuthSpec variants carry only the opaque `secret_ref` handle
//! this repo mints.
//!
//! **Reveal-never.** There is no plaintext column and no update-in-place.
//! `get` returns the sealed bytes + `set_at` only; the caller unseals.
//! Rotation = [`insert`](CredentialSecretsRepository::insert) a fresh row
//! (new `secret_ref`) then [`tombstone`](CredentialSecretsRepository::tombstone)
//! the old one — the prior plaintext is never re-fetchable. `sweep`
//! hard-deletes tombstoned rows past a grace cutoff.

use super::agent::RepoError;
use sqlx::Row;
use sqlx::SqlitePool;

/// A sealed credential row as stored. Never contains plaintext — the
/// caller unseals `sealed_value` with the [`crate::secret::CredentialSealingKey`].
#[derive(Debug, Clone)]
pub struct SealedSecret {
    pub secret_ref: String,
    pub sealed_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub set_at: i64,
}

/// Repository for the `credential_secrets` table.
#[derive(Clone)]
pub struct CredentialSecretsRepository {
    pool: SqlitePool,
}

impl CredentialSecretsRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Store sealed bytes under a freshly-minted opaque `secret_ref` and
    /// return the ref. The caller records the ref in the registration /
    /// override AuthSpec. Never overwrites an existing row — rotation is
    /// insert-new + tombstone-old.
    pub async fn insert(&self, sealed_value: &[u8], nonce: &[u8]) -> Result<String, RepoError> {
        let secret_ref = new_secret_ref()?;
        let now = unix_now();
        sqlx::query(
            "INSERT INTO credential_secrets (secret_ref, sealed_value, nonce, set_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&secret_ref)
        .bind(sealed_value)
        .bind(nonce)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(secret_ref)
    }

    /// Fetch a live (non-tombstoned) sealed secret by ref. Returns
    /// `Ok(None)` when the ref is absent or has been tombstoned — the
    /// injector then fails the request loud (never a silent no-inject).
    pub async fn get(&self, secret_ref: &str) -> Result<Option<SealedSecret>, RepoError> {
        let row = sqlx::query(
            "SELECT secret_ref, sealed_value, nonce, set_at \
             FROM credential_secrets \
             WHERE secret_ref = ? AND tombstoned_at IS NULL",
        )
        .bind(secret_ref)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(SealedSecret {
            secret_ref: row.get("secret_ref"),
            sealed_value: row.get("sealed_value"),
            nonce: row.get("nonce"),
            set_at: row.get("set_at"),
        }))
    }

    /// Mark a secret tombstoned (rotation or explicit clear). Returns
    /// `true` when a live row was tombstoned, `false` when the ref was
    /// absent or already tombstoned (idempotent). A tombstoned row is
    /// immediately invisible to `get`.
    pub async fn tombstone(&self, secret_ref: &str) -> Result<bool, RepoError> {
        let now = unix_now();
        let res = sqlx::query(
            "UPDATE credential_secrets SET tombstoned_at = ? \
             WHERE secret_ref = ? AND tombstoned_at IS NULL",
        )
        .bind(now)
        .bind(secret_ref)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Hard-delete tombstoned rows whose `tombstoned_at` is strictly
    /// before `cutoff` (unix seconds). Returns the number removed. Live
    /// rows are never touched. Called on the retention sweep interval.
    pub async fn sweep(&self, cutoff: i64) -> Result<u64, RepoError> {
        let res = sqlx::query(
            "DELETE FROM credential_secrets \
             WHERE tombstoned_at IS NOT NULL AND tombstoned_at < ?",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Test-only accessor for the underlying pool.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

/// Mint an opaque `cs_`-prefixed secret ref from 16 random bytes.
fn new_secret_ref() -> Result<String, RepoError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| RepoError::Rng(e.to_string()))?;
    let mut s = String::with_capacity(3 + 32);
    s.push_str("cs_");
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::open_and_migrate;
    use tempfile::TempDir;

    async fn fresh() -> (TempDir, CredentialSecretsRepository) {
        let dir = TempDir::new().unwrap();
        let pool = open_and_migrate(&dir.path().join("db.sqlite"))
            .await
            .unwrap();
        (dir, CredentialSecretsRepository::new(pool))
    }

    #[tokio::test]
    async fn insert_get_roundtrip() {
        let (_d, repo) = fresh().await;
        let r = repo.insert(b"sealed-ct", b"nonce12bytes").await.unwrap();
        assert!(r.starts_with("cs_"));
        let got = repo.get(&r).await.unwrap().unwrap();
        assert_eq!(got.secret_ref, r);
        assert_eq!(got.sealed_value, b"sealed-ct");
        assert_eq!(got.nonce, b"nonce12bytes");
        assert!(got.set_at > 0);
    }

    #[tokio::test]
    async fn get_returns_none_when_absent() {
        let (_d, repo) = fresh().await;
        assert!(repo.get("cs_does_not_exist").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn secret_refs_are_unique() {
        let (_d, repo) = fresh().await;
        let a = repo.insert(b"a", b"n").await.unwrap();
        let b = repo.insert(b"b", b"n").await.unwrap();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn tombstone_hides_row_from_get() {
        let (_d, repo) = fresh().await;
        let r = repo.insert(b"ct", b"n").await.unwrap();
        assert!(repo.tombstone(&r).await.unwrap());
        assert!(
            repo.get(&r).await.unwrap().is_none(),
            "tombstoned row must be invisible to get"
        );
    }

    #[tokio::test]
    async fn tombstone_is_idempotent() {
        let (_d, repo) = fresh().await;
        let r = repo.insert(b"ct", b"n").await.unwrap();
        assert!(repo.tombstone(&r).await.unwrap());
        assert!(
            !repo.tombstone(&r).await.unwrap(),
            "second tombstone is a no-op"
        );
        assert!(!repo.tombstone("cs_absent").await.unwrap());
    }

    #[tokio::test]
    async fn sweep_removes_tombstoned_past_cutoff_only() {
        let (_d, repo) = fresh().await;
        let live = repo.insert(b"live", b"n").await.unwrap();
        let dead = repo.insert(b"dead", b"n").await.unwrap();
        repo.tombstone(&dead).await.unwrap();

        // Cutoff far in the future → the tombstoned row is swept, the
        // live row is untouched.
        let removed = repo.sweep(i64::MAX).await.unwrap();
        assert_eq!(removed, 1);
        // Live row still present.
        assert!(repo.get(&live).await.unwrap().is_some());
        // And it's a hard delete — even a raw count sees it gone.
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM credential_secrets WHERE secret_ref = ?")
                .bind(&dead)
                .fetch_one(repo.pool())
                .await
                .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn sweep_respects_cutoff() {
        let (_d, repo) = fresh().await;
        let r = repo.insert(b"ct", b"n").await.unwrap();
        repo.tombstone(&r).await.unwrap();
        // Cutoff in the distant past → nothing swept (tombstoned_at >= cutoff).
        let removed = repo.sweep(0).await.unwrap();
        assert_eq!(removed, 0);
    }
}
