use super::*;
use crate::oauth::sealing::SealingKey;
use sqlx::{Sqlite, sqlite::SqliteArguments};

type Query<'a> = sqlx::query::Query<'a, Sqlite, SqliteArguments<'a>>;
struct Tokens {
    access: Option<(Vec<u8>, Vec<u8>)>,
    refresh: Option<(Vec<u8>, Vec<u8>)>,
    account: Option<String>,
}
impl Tokens {
    fn seal(
        key: &SealingKey,
        access: Option<&str>,
        refresh: Option<&str>,
    ) -> Result<Self, OauthSessionError> {
        Ok(Self {
            access: access.map(|t| key.seal(t.as_bytes())).transpose()?,
            refresh: refresh.map(|t| key.seal(t.as_bytes())).transpose()?,
            account: access.and_then(crate::oauth::jwt::extract_chatgpt_account_id),
        })
    }
}

impl OauthSessionRepository {
    /// Insert a new incarnation. Return only its materialized, committed row.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        key: &SealingKey,
        name: &str,
        session_label: &str,
        refresh_token: &str,
        access_token: Option<&str>,
        access_token_expires_at: Option<i64>,
        scope: &str,
    ) -> Result<OauthSession, OauthSessionError> {
        let kind: Option<String> =
            sqlx::query_scalar("SELECT kind FROM oauth_sessions WHERE name=? AND session_label=?")
                .bind(name)
                .bind(session_label)
                .fetch_optional(&self.pool)
                .await?;
        if kind.as_deref().is_some_and(|k| k != "legacy") {
            return Err(OauthSessionError::UnsupportedKind);
        }
        let tokens = Tokens::seal(key, access_token, Some(refresh_token))?;
        self.commit_row(
            key,
            create_query(name, session_label, scope, access_token_expires_at, &tokens),
        )
        .await
    }

    /// CAS against the snapshot that initiated the exchange; never upsert.
    /// An omitted rotated refresh token preserves the matched sealed pair.
    pub async fn update_tokens(
        &self,
        key: &SealingKey,
        expected: &OauthSession,
        new_access_token: &str,
        new_access_token_expires_at: i64,
        new_refresh_token: Option<&str>,
    ) -> Result<OauthSession, OauthSessionError> {
        self.write_tokens(
            key,
            expected,
            new_access_token,
            new_access_token_expires_at,
            new_refresh_token,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn write_tokens(
        &self,
        key: &SealingKey,
        expected: &OauthSession,
        access: &str,
        expiry: i64,
        refresh: Option<&str>,
        pending: bool,
    ) -> Result<OauthSession, OauthSessionError> {
        let tokens = Tokens::seal(key, Some(access), refresh)?;
        self.commit_row(key, update_query(expected, expiry, &tokens).bind(pending))
            .await
    }

    pub(super) async fn commit_row(
        &self,
        key: &SealingKey,
        query: Query<'_>,
    ) -> Result<OauthSession, OauthSessionError> {
        let mut tx = self.pool.begin().await?;
        // Unique incarnation permits at most one row; RETURNING proves one matched.
        let row = query
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(OauthSessionError::Stale)?;
        // Decode before COMMIT; return only afterward. No label-only readback.
        let committed = read::decode(key, row)?;
        #[cfg(test)]
        crate::oauth::refresh::recovery_barrier::complete("decoded", &committed).await;
        tx.commit().await?;
        #[cfg(test)]
        crate::oauth::refresh::recovery_barrier::complete("committed", &committed).await;
        Ok(committed)
    }
}

fn create_query<'a>(
    name: &'a str,
    label: &'a str,
    scope: &'a str,
    expiry: Option<i64>,
    t: &'a Tokens,
) -> Query<'a> {
    let now = unix_now();
    sqlx::query(include_str!("create.sql"))
        .bind(name)
        .bind(label)
        .bind(t.refresh.as_ref().map(|(ct, _)| ct))
        .bind(t.refresh.as_ref().map(|(_, n)| n))
        .bind(t.access.as_ref().map(|(ct, _)| ct))
        .bind(t.access.as_ref().map(|(_, n)| n))
        .bind(expiry)
        .bind(scope)
        .bind(now)
        .bind(now)
        .bind(&t.account)
}

fn update_query<'a>(expected: &'a OauthSession, expiry: i64, t: &'a Tokens) -> Query<'a> {
    sqlx::query(include_str!("update.sql"))
        .bind(t.access.as_ref().map(|(ct, _)| ct))
        .bind(t.access.as_ref().map(|(_, n)| n))
        .bind(expiry)
        .bind(t.refresh.as_ref().map(|(ct, _)| ct))
        .bind(t.refresh.as_ref().map(|(_, n)| n))
        .bind(&t.account)
        .bind(unix_now())
        .bind(expected.incarnation)
        .bind(&expected.name)
        .bind(&expected.session_label)
        .bind(expected.token_version)
}
