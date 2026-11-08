use super::*;
use crate::oauth::sealing::SealingKey;
use secrecy::SecretString;
use sqlx::{Row, sqlite::SqliteRow};

impl OauthSessionRepository {
    /// Read the current row. This is not authority to write a later incarnation.
    pub async fn get(
        &self,
        key: &SealingKey,
        name: &str,
        session_label: &str,
    ) -> Result<Option<OauthSession>, OauthSessionError> {
        let row = sqlx::query("SELECT * FROM oauth_sessions WHERE name = ? AND session_label = ?")
            .bind(name)
            .bind(session_label)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| decode(key, r)).transpose()
    }
    /// List `(name, session_label)` pairs whose
    /// `access_token_expires_at` is at or before the supplied
    /// threshold and which are not degraded. Used by the background
    /// refresh task. ADR-0005 D3.
    pub async fn list_pending_refresh(
        &self,
        threshold_unix_secs: i64,
    ) -> Result<Vec<(String, String)>, OauthSessionError> {
        let rows = sqlx::query(
            "SELECT name, session_label FROM oauth_sessions \
             WHERE kind = 'legacy' AND degraded = 0 AND refresh_pending = 0 AND access_token_expires_at IS NOT NULL \
               AND access_token_expires_at <= ? \
             ORDER BY access_token_expires_at ASC",
        )
        .bind(threshold_unix_secs)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("name"),
                    r.get::<String, _>("session_label"),
                )
            })
            .collect())
    }

    /// List all `(name, session_label)` pairs in the table. Used by
    /// `locksmith oauth list` (Phase G CLI) for operator visibility.
    /// Does not unseal tokens — pure metadata query.
    pub async fn list_all(&self) -> Result<Vec<SessionMetadata>, OauthSessionError> {
        let rows = sqlx::query(
            "SELECT name, session_label, degraded, access_token_expires_at, refresh_pending \
             FROM oauth_sessions WHERE kind = 'legacy' ORDER BY name, session_label",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let degraded: i64 = r.get("degraded");
                (
                    r.get::<String, _>("name"),
                    r.get::<String, _>("session_label"),
                    degraded != 0,
                    r.get::<Option<i64>, _>("access_token_expires_at"),
                    r.get::<i64, _>("refresh_pending") != 0,
                )
            })
            .collect())
    }
}

pub(super) fn decode(key: &SealingKey, row: SqliteRow) -> Result<OauthSession, OauthSessionError> {
    if row.try_get::<String, _>("kind")? != "legacy" {
        return Err(OauthSessionError::UnsupportedKind);
    }
    let refresh_ct: Vec<u8> = row.try_get("refresh_token_ciphertext")?;
    let refresh_nonce: Vec<u8> = row.try_get("refresh_token_nonce")?;
    Ok(OauthSession {
        incarnation: row.try_get("incarnation")?,
        token_version: row.try_get("token_version")?,
        refresh_pending: row.try_get::<i64, _>("refresh_pending")? != 0,
        name: row.try_get("name")?,
        session_label: row.try_get("session_label")?,
        refresh_token: unseal(key, &refresh_ct, &refresh_nonce)?,
        access_token: access_token(key, &row)?,
        access_token_expires_at: row.try_get("access_token_expires_at")?,
        scope: row.try_get("scope")?,
        degraded: row.try_get::<i64, _>("degraded")? != 0,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        account_id: row.try_get("account_id")?,
    })
}

fn unseal(key: &SealingKey, ct: &[u8], nonce: &[u8]) -> Result<SecretString, OauthSessionError> {
    let bytes = key.unseal(ct, nonce)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| OauthSessionError::Invariant("token plaintext is not UTF-8"))?;
    Ok(SecretString::from(text))
}

fn access_token(
    key: &SealingKey,
    row: &SqliteRow,
) -> Result<Option<SecretString>, OauthSessionError> {
    let ct: Option<Vec<u8>> = row.try_get("access_token_ciphertext")?;
    let nonce: Option<Vec<u8>> = row.try_get("access_token_nonce")?;
    match (ct, nonce) {
        (Some(ct), Some(nonce)) => Ok(Some(unseal(key, &ct, &nonce)?)),
        (None, None) => Ok(None),
        _ => Err(OauthSessionError::Invariant(
            "access token ciphertext / nonce out of sync",
        )),
    }
}
