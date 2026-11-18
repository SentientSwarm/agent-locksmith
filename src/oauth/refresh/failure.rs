use super::*;

/// Mark a failed refresh: degraded when it failed before its claim,
/// reported as needing reconnection when after it, and in both cases
/// written to the operational log (AGENT-302). Background and inline
/// refreshes both end here.
pub(crate) async fn record_failure(
    repo: &OauthSessionRepository,
    session: &OauthSession,
    error: &RefreshError,
    emitter: Option<&crate::operational_log_sink::OperationalLogEmitter>,
) {
    if repo.mark_degraded(session).await.is_err() {
        // AGENT-302: a failure after the refresh claimed the session leaves
        // it pending (custody uncertain), so it can't be marked degraded.
        // It needs signing in again all the same, so say so.
        if repo.held_by_claim(session).await.unwrap_or(false) {
            warn!(name = %session.name, session_label = %session.session_label,
                cause = error.audit_cause(), "oauth refresh failed; session needs reconnecting");
            if let Some(emitter) = emitter {
                emitter.emit(
                    crate::repo::LogLevel::Warn,
                    crate::repo::LogComponent::Oauth,
                    "oauth_refresh_reconnect_required",
                    "oauth refresh failed after its claim; session must be signed in again",
                    Some(serde_json::json!({"registration": session.name,
                        "session_label": session.session_label, "cause": error.audit_cause()})),
                );
            }
            return;
        }
        warn!(name = %session.name, session_label = %session.session_label,
            cause = error.audit_cause(), "oauth refresh failed; degradation not committed");
        return;
    }
    warn!(name = %session.name, session_label = %session.session_label,
        cause = error.audit_cause(), "oauth refresh failed; session marked degraded");
    if let Some(emitter) = emitter {
        emitter.emit(
            crate::repo::LogLevel::Warn,
            crate::repo::LogComponent::Oauth,
            "oauth_refresh_degraded",
            "oauth refresh failed; session marked degraded",
            Some(serde_json::json!({"registration": session.name,
                "session_label": session.session_label, "cause": error.audit_cause()})),
        );
    }
}
