//! AGENT-266 — the proxy side of per-agent rate limits: refuse an agent
//! over its limit with 429 before anything is sent upstream, and hold a
//! concurrency permit until the response body is dropped.

use super::{RequestCtx, audit_record};
use crate::app::AppState;
use crate::ratelimit::Permit;
use crate::repo::audit::{AuditRepository, Decision, EventClass};
use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header::RETRY_AFTER};
use axum::response::{IntoResponse, Json, Response};
use futures_util::StreamExt;
use serde_json::json;

/// Admit the request or answer 429. Identity-less (legacy) requests are
/// never limited: limits are per agent.
pub(super) async fn check(
    state: &AppState,
    ctx: &RequestCtx,
    identity: Option<&crate::auth_v2::AgentIdentity>,
) -> Result<Option<Permit>, Response> {
    let Some(identity) = identity else {
        return Ok(None);
    };
    match state.rate_limits.check(identity.id, &ctx.tool_name) {
        Ok(permit) => Ok(permit),
        Err(limited) => Err(refuse(&state.audit, ctx, limited).await),
    }
}

async fn refuse(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    limited: crate::ratelimit::Limited,
) -> Response {
    let reason = if limited.concurrency {
        "concurrency"
    } else {
        "rate"
    };
    // AGENT-272: at most one row per (agent, route) a minute; the row
    // counts the refusals since the slot's previous one.
    if let Some(suppressed) = limited.audit {
        let mut event = ctx.audit_event_base();
        event.event_class = EventClass::Security;
        event.event = "rate_limited".to_string();
        event.status = Some(429);
        event.decision = Decision::Denied;
        event.details = Some(json!({
            "reason": reason,
            "retry_after": limited.retry_after_secs,
            "suppressed": suppressed,
        }));
        audit_record(audit, event).await;
    }
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({ "error": {
            "message": "rate limit exceeded",
            "type": "rate_limit_error",
            "code": "rate_limited",
        } })),
    )
        .into_response();
    resp.headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(limited.retry_after_secs));
    resp
}

/// Keep `permit` until the response body is finished or dropped.
pub(super) fn hold(resp: Response, permit: Option<Permit>) -> Response {
    match permit {
        None => resp,
        Some(permit) => resp.map(|body| {
            Body::from_stream(body.into_data_stream().map(move |chunk| {
                let _held = &permit;
                chunk
            }))
        }),
    }
}
