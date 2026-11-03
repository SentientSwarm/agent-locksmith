//! Selected OAuth custody; network attempts carry the original row identity.
#![allow(clippy::result_large_err)]
use super::*;
use crate::{app::OauthRuntime, oauth::OauthSession};

pub(super) struct OauthUnavailable {
    pub response: Response,
    pub audit_cause: &'static str,
}

fn unavailable(code: &'static str, cause: &'static str, message: &str) -> OauthUnavailable {
    OauthUnavailable {
        response: (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": {
                "type": "auth_error", "code": code, "message": message,
            }})),
        )
            .into_response(),
        audit_cause: cause,
    }
}

pub(super) async fn resolve_oauth_token(
    state: &AppState,
    target: &ProxyTarget,
    label: &str,
) -> Result<ProxyAuth, OauthUnavailable> {
    let rt = state.oauth.as_ref().ok_or_else(|| {
        unavailable(
            "oauth_sealing_key_unset",
            "sealing_key_unset",
            "OAuth registration requires LOCKSMITH_OAUTH_SEALING_KEY at daemon startup",
        )
    })?;
    let lock = rt.locks.get(&target.name, label).await;
    let _guard = lock.lock().await;
    if !selection::oauth_consistent(state, target, label).await {
        return Err(unavailable(
            "oauth_selection_unavailable",
            "selection_unavailable",
            "OAuth session requires consistent explicit selections",
        ));
    }
    let session = current(rt, target, label).await?;
    validate(&session)?;
    let active = if needs_refresh(&session) {
        refresh(rt, target, &session).await?
    } else {
        session
    };
    Ok(materialize(active, target))
}

fn materialize(active: OauthSession, target: &ProxyTarget) -> ProxyAuth {
    let audit_mode = match &target.auth {
        ProxyAuth::Oauth { audit_mode, .. } => *audit_mode,
        _ => "oauth_unknown",
    };
    ProxyAuth::Oauth {
        audit_mode,
        oauth_session_id: active.audit_session_id(),
        access_token: active.access_token,
        account_id: active.account_id,
    }
}

async fn current(
    rt: &OauthRuntime,
    target: &ProxyTarget,
    label: &str,
) -> Result<OauthSession, OauthUnavailable> {
    match rt.sessions.get(&rt.sealing_key, &target.name, label).await {
        Ok(Some(s)) => Ok(s),
        Ok(None) => Err(unavailable(
            "oauth_session_missing",
            "session_missing",
            "OAuth session not bootstrapped for this registration",
        )),
        Err(_) => {
            tracing::warn!(name = %target.name, "oauth session read failed");
            Err(unavailable(
                "oauth_session_read_failed",
                "session_read_failed",
                "OAuth session unavailable (sealing failure)",
            ))
        }
    }
}

fn validate(session: &OauthSession) -> Result<(), OauthUnavailable> {
    if session.degraded {
        return Err(unavailable(
            "oauth_refresh_failed",
            "degraded",
            "OAuth session degraded — operator must re-bootstrap",
        ));
    }
    if session
        .access_token
        .as_ref()
        .is_some_and(|t| t.expose_secret().is_empty())
        || session.refresh_token.expose_secret().is_empty()
    {
        return Err(unavailable(
            "oauth_session_empty",
            "session_empty",
            "selected OAuth session contains an empty token",
        ));
    }
    Ok(())
}

fn needs_refresh(session: &OauthSession) -> bool {
    match (&session.access_token, session.access_token_expires_at) {
        (None, _) => true,
        (Some(_), Some(exp)) if exp <= now_secs() + 60 => true,
        _ => false,
    }
}

async fn refresh(
    rt: &OauthRuntime,
    target: &ProxyTarget,
    session: &OauthSession,
) -> Result<OauthSession, OauthUnavailable> {
    let selected = target.oauth_selection.as_ref().ok_or_else(|| {
        unavailable(
            "oauth_selection_unavailable",
            "selection_unavailable",
            "explicit OAuth selection is unavailable",
        )
    })?;
    match crate::oauth::refresh::refresh_selected_session(
        &rt.sessions,
        selected,
        &rt.sealing_key,
        &rt.refresh_client,
        session,
    )
    .await
    {
        Ok(committed) => Ok(committed),
        Err(e) => {
            let _ = rt.sessions.mark_degraded(session).await;
            Err(refresh_failure(target, &e))
        }
    }
}

fn refresh_failure(
    target: &ProxyTarget,
    error: &crate::oauth::refresh::RefreshError,
) -> OauthUnavailable {
    tracing::warn!(name = %target.name, cause = error.audit_cause(), "oauth refresh failed inline");
    unavailable(
        "oauth_refresh_failed",
        error.audit_cause(),
        "OAuth refresh failed — operator must re-bootstrap",
    )
}
