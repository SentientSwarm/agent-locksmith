use super::*;
use crate::{auth_v2::AgentIdentity, registrations::admission::activation};

pub(super) async fn target(
    state: &AppState,
    ctx: &RequestCtx,
    extensions: &axum::http::Extensions,
) -> Result<ProxyTarget, Box<Response>> {
    let Some(identity) = extensions.get::<AgentIdentity>() else {
        return Err(Box::new(
            selection::record_failure(&state.audit, ctx, selection::Failure::IdentityRequired)
                .await,
        ));
    };
    if state.agent_creds.is_none() {
        return Err(Box::new(
            selection::record_failure(&state.audit, ctx, selection::Failure::StoreUnavailable)
                .await,
        ));
    }
    let repo = state.registrations.as_ref().expect("database path");
    let mut rows = match repo.http_admissions(identity, Some(&ctx.tool_name)).await {
        Ok(rows) => rows,
        Err(_) => {
            return Err(Box::new(
                selection::record_failure(&state.audit, ctx, selection::Failure::StoreUnavailable)
                    .await,
            ));
        }
    };
    let Some(row) = rows.pop() else {
        return Err(Box::new(record_tool_not_found(&state.audit, ctx).await));
    };
    if !row.agent_active {
        let mut event = ctx.audit_event_base();
        event.event_class = EventClass::Security;
        event.event = "authz_denied".into();
        event.status = Some(401);
        event.decision = Decision::Denied;
        event.details = Some(json!({"reason":"agent_inactive_at_admission"}));
        audit_record(&state.audit, event).await;
        return Err(Box::new((StatusCode::UNAUTHORIZED, Json(json!({"error": {
            "type":"auth_error", "code":"invalid_credential", "message":"agent is no longer active"
        }}))).into_response()));
    }
    if let Err(reason) = row.grant {
        return Err(Box::new(
            record_authz_denied(&state.audit, ctx, reason).await,
        ));
    }
    if row.registration.disabled
        || row.registration.protocol != crate::registrations::Protocol::Http
    {
        return Err(Box::new(record_tool_not_found(&state.audit, ctx).await));
    }
    if activation(&row.registration, Some(&state.catalog.load())) != "active" {
        return Err(Box::new(
            unavailable(state, ctx, "connection_not_active").await,
        ));
    }
    let Some(account) = row.account else {
        return Err(Box::new(
            selection::record_failure(&state.audit, ctx, selection::Failure::Missing).await,
        ));
    };
    let mut target = ProxyTarget::from_registration(&row.registration);
    if row.registration.broker.is_some() {
        return broker(state, ctx, target, &row.registration, account, identity).await;
    }
    if let Err(failure) = selection::apply_spec(&mut target, account) {
        return Err(Box::new(
            selection::record_failure(&state.audit, ctx, failure).await,
        ));
    }
    target.auth_source = "agent_override";
    Ok(target)
}

/// Brokered routes phase 3: the agent's explicit `broker` selection admits
/// it, and the route's own key (never a per-agent credential) is sent. A
/// key that is unset or not a broker key kind fails closed.
async fn broker(
    state: &AppState,
    ctx: &RequestCtx,
    mut target: ProxyTarget,
    registration: &crate::registrations::Registration,
    account: AuthSpec,
    identity: &AgentIdentity,
) -> Result<ProxyTarget, Box<Response>> {
    use crate::registrations::broker_health::HealthStatus;
    if state
        .broker_health
        .get(&registration.name)
        .is_some_and(|h| h.status == HealthStatus::Down)
    {
        return Err(Box::new(backend_unavailable(state, ctx).await));
    }
    let key = &registration.auth;
    let usable = account == AuthSpec::Broker
        && crate::registrations::broker::is_broker_key(key)
        && selection::apply_spec(&mut target, key.clone()).is_ok();
    if !usable {
        return Err(Box::new(
            selection::record_failure(&state.audit, ctx, selection::Failure::CredentialUnavailable)
                .await,
        ));
    }
    target.auth_source = "broker";
    target.broker_agent = Some(identity.public_id.clone());
    Ok(target)
}

/// The broker failed its last health probe: refuse without dispatch.
async fn backend_unavailable(state: &AppState, ctx: &RequestCtx) -> Response {
    let mut event = ctx.audit_event_base();
    event.status = Some(503);
    event.decision = Decision::Denied;
    event.details = Some(json!({ "cause": "backend_unavailable", "backend_kind": "broker" }));
    audit_record(&state.audit, event).await;
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": {
            "type": "availability_error", "code": "backend_unavailable",
            "message": "the route's broker failed its health probe; try again later"
        }})),
    )
        .into_response()
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
