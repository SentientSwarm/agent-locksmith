use super::*;

pub(super) async fn record_failure(
    repo: &OauthSessionRepository,
    session: &OauthSession,
    error: &RefreshError,
    emitter: Option<&crate::operational_log_sink::OperationalLogEmitter>,
) {
    if repo.mark_degraded(session).await.is_err() {
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
