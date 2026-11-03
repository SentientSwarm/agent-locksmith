use super::*;
use crate::{auth_v2::AgentIdentity, registrations::admission::activation};

pub(super) async fn target(
    state: &AppState,
    ctx: &RequestCtx,
    extensions: &axum::http::Extensions,
) -> Result<ProxyTarget, Response> {
    let Some(identity) = extensions.get::<AgentIdentity>() else {
        return Err(selection::record_failure(
            &state.audit,
            ctx,
            selection::Failure::IdentityRequired,
        )
        .await);
    };
    if state.agent_creds.is_none() {
        return Err(selection::record_failure(
            &state.audit,
            ctx,
            selection::Failure::StoreUnavailable,
        )
        .await);
    }
    let repo = state.registrations.as_ref().expect("database path");
    let mut rows = match repo.http_admissions(identity, Some(&ctx.tool_name)).await {
        Ok(rows) => rows,
        Err(_) => {
            return Err(selection::record_failure(
                &state.audit,
                ctx,
                selection::Failure::StoreUnavailable,
            )
            .await);
        }
    };
    let Some(row) = rows.pop() else {
        return Err(record_tool_not_found(&state.audit, ctx).await);
    };
    if !row.agent_active {
        let mut event = ctx.audit_event_base();
        event.event_class = EventClass::Security;
        event.event = "authz_denied".into();
        event.status = Some(401);
        event.decision = Decision::Denied;
        event.details = Some(json!({"reason":"agent_inactive_at_admission"}));
        audit_record(&state.audit, event).await;
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error": {
            "type":"auth_error", "code":"invalid_credential", "message":"agent is no longer active"
        }}))).into_response());
    }
    if let Err(reason) = row.grant {
        return Err(record_authz_denied(&state.audit, ctx, reason).await);
    }
    if row.registration.disabled {
        return Err(record_tool_not_found(&state.audit, ctx).await);
    }
    if activation(&row.registration, Some(&state.catalog.load())) != "active" {
        return Err(unavailable(state, ctx, "connection_not_active").await);
    }
    let Some(account) = row.account else {
        return Err(
            selection::record_failure(&state.audit, ctx, selection::Failure::Missing).await,
        );
    };
    let mut target = ProxyTarget::from_registration(&row.registration);
    if let Err(failure) = selection::apply_spec(&mut target, account) {
        return Err(selection::record_failure(&state.audit, ctx, failure).await);
    }
    target.auth_source = "agent_override";
    Ok(target)
}

async fn unavailable(state: &AppState, ctx: &RequestCtx, code: &str) -> Response {
    let mut event = ctx.audit_event_base();
    event.status = Some(503);
    event.decision = Decision::Denied;
    event.details = Some(json!({"cause":code}));
    audit_record(&state.audit, event).await;
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": {
        "type":"availability_error", "code":code,
        "message":"connection admission unavailable; ask the operator to check persisted configuration and runtime activation"
    }}))).into_response()
}
