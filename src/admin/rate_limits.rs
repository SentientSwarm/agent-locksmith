//! AGENT-266 — operator API for per-agent, per-route rate limits.
//!
//! `GET /admin/operator/rate-limits`, and `PUT` / `DELETE`
//! `/admin/operator/rate-limits/{route}` (`?agent=` on delete). Each write
//! is audited (`rate_limit_set` / `rate_limit_deleted`, operator class)
//! and reloads the proxy's limiter, so it applies without a restart.

use super::service::now_ms;
use super::uds::{UdsState, admin_err_response};
use crate::auth_v2::OperatorIdentity;
use crate::ratelimit::{Limit, RateLimits};
use crate::repo::audit::{AuditEvent, Decision, EventClass};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetInput {
    pub requests_per_minute: u32,
    #[serde(default)]
    pub max_concurrent: Option<u32>,
    /// Agent public id or name; absent sets the route default.
    #[serde(default)]
    pub agent: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentQuery {
    #[serde(default)]
    pub agent: Option<String>,
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "rate_limits_unavailable",
        "rate limits could not be read or written",
    )
}

/// AGENT-272: the write is stored and audited, but the limiter could not
/// be reloaded, so the proxy still applies the old limits until the next
/// change or restart.
fn not_applied(route: &str, e: &sqlx::Error) -> Response {
    tracing::error!(route, error = %e, "rate limit stored but the limiter could not reload");
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "rate_limits_not_applied",
        "the change is stored, but the proxy could not load it; it applies at the next change or restart",
    )
}

fn wired(state: &UdsState) -> Result<Arc<RateLimits>, Box<Response>> {
    state.admin.rate_limits().ok_or_else(|| {
        Box::new(error(
            StatusCode::NOT_FOUND,
            "not_found",
            "rate limits are not enabled",
        ))
    })
}

/// Resolve an optional agent reference to (id, public id).
async fn agent(
    state: &UdsState,
    op: &OperatorIdentity,
    agent: Option<&str>,
) -> Result<Option<(i64, String)>, Response> {
    match agent {
        None => Ok(None),
        Some(a) => match state.admin.get_agent(op, a).await {
            Ok(r) => Ok(Some((r.id, r.public_id))),
            Err(e) => Err(admin_err_response(e)),
        },
    }
}

/// AGENT-272 — only the `/api/*` proxy enforces limits, so a limit on
/// any other registration would be listed and audited but never applied.
fn limitable(r: &crate::registrations::Registration) -> bool {
    r.protocol == crate::registrations::Protocol::Http
        && r.kind != crate::registrations::Kind::Infra
}

/// `GET /admin/operator/rate-limits`. With registrations wired, each row
/// says whether its route is currently one the proxy limits (AGENT-272):
/// a limit outlives its registration and applies again if the route
/// returns as an HTTP model or tool.
pub(super) async fn op_list(
    State(state): State<UdsState>,
    Extension(_op): Extension<OperatorIdentity>,
) -> Response {
    let limits = match wired(&state) {
        Ok(l) => l,
        Err(r) => return *r,
    };
    let Ok(rows) = limits.repo.list().await else {
        return unavailable();
    };
    let mut out = Vec::with_capacity(rows.len());
    let mut seen = std::collections::HashMap::new();
    for row in rows {
        let mut value = json!(row);
        if let Some(regs) = &state.registrations {
            let enforced = match seen.get(&row.route) {
                Some(&e) => e,
                None => match regs.get(&row.route).await {
                    Ok(r) => *seen
                        .entry(row.route.clone())
                        .or_insert(r.as_ref().is_some_and(limitable)),
                    Err(_) => return unavailable(),
                },
            };
            value["enforced"] = json!(enforced);
        }
        out.push(value);
    }
    Json(json!({ "rate_limits": out })).into_response()
}

/// `PUT /admin/operator/rate-limits/{route}`.
pub(super) async fn op_set(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path(route): Path<String>,
    Json(input): Json<SetInput>,
) -> Response {
    let limits = match wired(&state) {
        Ok(l) => l,
        Err(r) => return *r,
    };
    if input.requests_per_minute == 0 || input.max_concurrent == Some(0) {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_rate_limit",
            "requests_per_minute and max_concurrent must be at least 1",
        );
    }
    if let Some(regs) = &state.registrations {
        match regs.get(&route).await {
            Ok(Some(r)) if !limitable(&r) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "route_not_limitable",
                    "rate limits apply only to HTTP model and tool routes served under /api",
                );
            }
            Ok(Some(_)) => {}
            Ok(None) => return error(StatusCode::NOT_FOUND, "route_not_found", "no such route"),
            Err(_) => return unavailable(),
        }
    }
    let who = match agent(&state, &op, input.agent.as_deref()).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let limit = Limit {
        requests_per_minute: input.requests_per_minute,
        max_concurrent: input.max_concurrent,
    };
    let agent_id = who.as_ref().map(|w| w.0);
    let written = limits.repo.set(&route, agent_id, limit, now_ms()).await;
    let mut details = json!({ "route": route, "limit": limit });
    if let Ok(Some(p)) = &written {
        details["previous"] = json!(p);
    }
    audit(
        &state,
        &op,
        "rate_limit_set",
        &route,
        who.as_ref(),
        written.is_ok(),
        details,
    )
    .await;
    if written.is_err() {
        return unavailable();
    }
    if let Err(e) = limits.reload().await {
        return not_applied(&route, &e);
    }
    Json(json!({ "route": route, "agent": who.map(|w| w.1), "limit": limit })).into_response()
}

/// `DELETE /admin/operator/rate-limits/{route}[?agent=A]`.
pub(super) async fn op_delete(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path(route): Path<String>,
    Query(q): Query<AgentQuery>,
) -> Response {
    let limits = match wired(&state) {
        Ok(l) => l,
        Err(r) => return *r,
    };
    let who = match agent(&state, &op, q.agent.as_deref()).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let agent_id = who.as_ref().map(|w| w.0);
    let previous = match limits.repo.delete(&route, agent_id).await {
        Ok(p) => p,
        Err(_) => return unavailable(),
    };
    if previous.is_none() {
        return error(
            StatusCode::NOT_FOUND,
            "rate_limit_not_found",
            "no such rate limit",
        );
    }
    let details = json!({ "route": route, "previous": previous });
    audit(
        &state,
        &op,
        "rate_limit_deleted",
        &route,
        who.as_ref(),
        true,
        details,
    )
    .await;
    if let Err(e) = limits.reload().await {
        return not_applied(&route, &e);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn audit(
    state: &UdsState,
    op: &OperatorIdentity,
    event: &str,
    route: &str,
    who: Option<&(i64, String)>,
    ok: bool,
    details: Value,
) {
    let event = AuditEvent {
        ts_ms: now_ms(),
        event_class: EventClass::Operator,
        event: event.into(),
        agent_public_id: who.map(|w| w.1.clone()),
        tool: Some(route.to_string()),
        decision: if ok {
            Decision::Allowed
        } else {
            Decision::Denied
        },
        details: Some(details),
        ..AuditEvent::default()
    };
    state.admin.audit_for_operator(op, event).await;
}
