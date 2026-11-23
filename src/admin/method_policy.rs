//! Operator-only live per-binding method policy writes.
use super::uds::{UdsState, admin_err_response};
use crate::{
    auth_v2::OperatorIdentity,
    method_policy::MethodPolicy,
    repo::audit::{AuditEvent, Decision, EventClass},
};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

pub(super) async fn set(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((agent, route)): Path<(String, String)>,
    Json(policy): Json<MethodPolicy>,
) -> Response {
    if !policy.validate() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error":{
            "code":"invalid_method_policy", "message":"use exact methods, family.* or *; at most 256 patterns"
        }}))).into_response();
    }
    write(state, op, agent, route, Some(policy)).await
}
pub(super) async fn clear(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((agent, route)): Path<(String, String)>,
) -> Response {
    write(state, op, agent, route, None).await
}
async fn write(
    state: UdsState,
    op: OperatorIdentity,
    agent: String,
    route: String,
    policy: Option<MethodPolicy>,
) -> Response {
    let agent = match state.admin.get_agent(&op, &agent).await {
        Ok(a) => a,
        Err(e) => return admin_err_response(e),
    };
    let Some(repo) = &state.agent_creds else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let result = repo
        .set_method_policy(agent.id, &route, policy.as_ref())
        .await;
    state
        .admin
        .audit_for_operator(
            &op,
            AuditEvent {
                ts_ms: super::service::now_ms(),
                event_class: EventClass::Operator,
                event: "method_policy_changed".into(),
                tool: Some(route.clone()),
                agent_public_id: Some(agent.public_id),
                decision: if result.is_ok() {
                    Decision::Allowed
                } else {
                    Decision::Denied
                },
                // Patterns are identifiers, not credential values.
                details: Some(json!({"policy":policy})),
                ..AuditEvent::default()
            },
        )
        .await;
    match result {
        Ok(()) => Json(json!({"registration":route, "method_policy":policy})).into_response(),
        Err(e) => admin_err_response(e.into()),
    }
}
