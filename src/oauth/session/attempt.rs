use super::*;
use crate::oauth::SealingKey;

/// Authority to complete one committed refresh claim. Reading a pending row
/// after restart cannot recreate this authority or permit a token replay.
pub struct RefreshAttempt {
    session: OauthSession,
}

impl RefreshAttempt {
    pub fn session(&self) -> &OauthSession {
        &self.session
    }
}

impl OauthSessionRepository {
    /// Commit uncertainty before any token-endpoint I/O, reserving a completion
    /// increment so an exhausted version can never consume a refresh token.
    pub async fn begin_refresh(
        &self,
        key: &SealingKey,
        expected: &OauthSession,
    ) -> Result<RefreshAttempt, OauthSessionError> {
        let query = sqlx::query(include_str!("begin_refresh.sql"))
            .bind(unix_now())
            .bind(expected.incarnation)
            .bind(&expected.name)
            .bind(&expected.session_label)
            .bind(expected.token_version);
        let session = self.commit_row(key, query).await?;
        Ok(RefreshAttempt { session })
    }

    /// Publish only the complete pair committed against this exact attempt.
    pub async fn complete_refresh(
        &self,
        key: &SealingKey,
        attempt: &RefreshAttempt,
        access: &str,
        expiry: i64,
        refresh: Option<&str>,
    ) -> Result<OauthSession, OauthSessionError> {
        self.write_tokens(key, &attempt.session, access, expiry, refresh, true)
            .await
    }
}
