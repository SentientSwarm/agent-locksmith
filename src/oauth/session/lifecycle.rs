use super::*;

impl OauthSessionRepository {
    /// Delete a session row entirely. Operator-initiated via
    /// `locksmith oauth revoke <name> [--label <label>]`. Does NOT
    /// call the provider's revoke endpoint (deferred to v1.1+).
    pub async fn delete(&self, name: &str, session_label: &str) -> Result<bool, OauthSessionError> {
        let result = sqlx::query("DELETE FROM oauth_sessions WHERE name = ? AND session_label = ?")
            .bind(name)
            .bind(session_label)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Failure cleanup may delete only the row originally created by that attempt.
    pub async fn delete_if_current(
        &self,
        expected: &OauthSession,
    ) -> Result<(), OauthSessionError> {
        let result = sqlx::query(include_str!("delete_current.sql"))
            .bind(expected.incarnation)
            .bind(&expected.name)
            .bind(&expected.session_label)
            .bind(expected.token_version)
            .execute(&self.pool)
            .await?;
        require_one(result.rows_affected())
    }

    /// Failed exchanges cannot degrade a replacement or a newer successful pair.
    pub async fn mark_degraded(&self, expected: &OauthSession) -> Result<(), OauthSessionError> {
        let result = sqlx::query(include_str!("degrade.sql"))
            .bind(unix_now())
            .bind(expected.incarnation)
            .bind(&expected.name)
            .bind(&expected.session_label)
            .bind(expected.token_version)
            .execute(&self.pool)
            .await?;
        require_one(result.rows_affected())
    }
}

fn require_one(rows: u64) -> Result<(), OauthSessionError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(OauthSessionError::Stale)
    }
}
