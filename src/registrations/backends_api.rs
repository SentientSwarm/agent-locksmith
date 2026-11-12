//! Brokered routes phase 2 — operator API for route backends.
//!
//! `GET  /admin/operator/routes/{route}/backends`
//! `PUT|GET|DELETE /admin/operator/routes/{route}/backends/{backend}`
//! `POST /admin/operator/routes/{route}/switch` (`If-Match: <revision>`)
//!
//! A switch keeps grants, moves bindings with the backend, refreshes the
//! runtime catalog and writes a `route_backend_switched` security audit row.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use super::api::{AdminRegistrationsState, registration_error_response};
use super::backends::{BackendError, BackendRepository, RouteBackend};
use super::{AuthSpec, Kind, Protocol, Registration, RegistrationError};
use crate::admin::AdminService;
use crate::auth_v2::OperatorIdentity;
use crate::config::EgressMode;
use crate::repo::audit::{AuditEvent, Decision, EventClass};

#[derive(Clone)]
pub struct BackendsState {
    pub regs: AdminRegistrationsState,
    pub admin: Arc<AdminService>,
}

pub fn router(state: BackendsState) -> Router {
    Router::new()
        .route("/routes/{route}/backends", get(list))
        .route(
            "/routes/{route}/backends/{backend}",
            get(get_one).put(put).delete(delete),
        )
        .route("/routes/{route}/switch", post(switch))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendBody {
    pub upstream: String,
    #[serde(default)]
    pub egress: Option<EgressMode>,
    #[serde(default)]
    pub upstream_ca_pem: Option<String>,
    pub auth: AuthSpec,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchBody {
    pub backend: String,
}

fn error(status: StatusCode, kind: &str, code: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "type": kind, "code": code, "message": code.replace('_', " ") } })),
    )
        .into_response()
}

fn backend_error(e: &BackendError) -> Response {
    match e {
        BackendError::NotFound => error(StatusCode::NOT_FOUND, "not_found", "unknown_name"),
        BackendError::ActiveBackend => error(StatusCode::CONFLICT, "conflict", "active_backend"),
        BackendError::RouteNotSwitchable => {
            error(StatusCode::CONFLICT, "conflict", "route_not_switchable")
        }
        BackendError::AuthUnsupported => {
            error(StatusCode::CONFLICT, "conflict", "backend_auth_unsupported")
        }
        BackendError::RevisionConflict => {
            error(StatusCode::CONFLICT, "conflict", "revision_conflict")
        }
        BackendError::Json(_) | BackendError::Db(_) => {
            tracing::error!("route backend store error");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal_error",
            )
        }
    }
}

fn switchable(r: &Registration) -> bool {
    matches!(r.kind, Kind::Tool | Kind::Model) && r.protocol == Protocol::Http && r.mcp.is_none()
}

fn oauth(a: &AuthSpec) -> bool {
    matches!(
        a,
        AuthSpec::OauthPkce { .. }
            | AuthSpec::OauthDeviceCode { .. }
            | AuthSpec::ControlledOauth { .. }
    )
}

/// The auth mechanism name only (the serde tag), never its parameters.
fn auth_kind(a: &AuthSpec) -> Value {
    serde_json::to_value(a)
        .ok()
        .and_then(|v| v.get("kind").cloned())
        .unwrap_or(Value::Null)
}

fn view(b: &RouteBackend) -> Value {
    json!({
        "name": b.name,
        "upstream": b.upstream,
        "egress": super::backends::egress_str(b.egress),
        "upstream_ca": b.upstream_ca_pem.as_deref().map(|pem| json!({
            "sha256": super::upstream_ca::sha256_hex(pem),
        })),
        "auth": b.auth,
        "created_at": b.created_at,
        "updated_at": b.updated_at,
    })
}

fn ca_sha256(pem: Option<&str>) -> Option<String> {
    pem.map(super::upstream_ca::sha256_hex)
}

async fn audit(
    st: &BackendsState,
    op: &OperatorIdentity,
    route: &str,
    event: &str,
    details: Value,
) {
    st.admin
        .audit(AuditEvent {
            ts_ms: super::backends::unix_now() * 1000,
            event_class: EventClass::Security,
            event: event.into(),
            operator_name: Some(op.name.clone()),
            tool: Some(route.into()),
            decision: Decision::Allowed,
            details: Some(details),
            ..AuditEvent::default()
        })
        .await;
}

/// The switchable route, or the response that refuses it.
async fn route_of(st: &BackendsState, route: &str) -> Result<Registration, Response> {
    match st.regs.repo.get(route).await {
        Ok(Some(r)) if switchable(&r) => Ok(r),
        Ok(Some(_)) => Err(backend_error(&BackendError::RouteNotSwitchable)),
        Ok(None) => Err(backend_error(&BackendError::NotFound)),
        Err(e) => Err(registration_error_response(&e)),
    }
}

async fn list(State(st): State<BackendsState>, Path(route): Path<String>) -> Response {
    if let Err(r) = route_of(&st, &route).await {
        return r;
    }
    let repo = BackendRepository::new(st.regs.repo.pool.clone());
    let (active, backends, rev) = match (
        repo.active_backend(&route).await,
        repo.list(&route).await,
        repo.revision(&route).await,
    ) {
        (Ok(a), Ok(b), Ok(r)) => (a, b, r),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return backend_error(&e),
    };
    Json(json!({
        "route": route,
        "active_backend": active,
        "revision": rev,
        "backends": backends.iter().map(view).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn get_one(
    State(st): State<BackendsState>,
    Path((route, backend)): Path<(String, String)>,
) -> Response {
    if let Err(r) = route_of(&st, &route).await {
        return r;
    }
    match BackendRepository::new(st.regs.repo.pool.clone())
        .get(&route, &backend)
        .await
    {
        Ok(Some(b)) => Json(view(&b)).into_response(),
        Ok(None) => backend_error(&BackendError::NotFound),
        Err(e) => backend_error(&e),
    }
}

async fn put(
    State(st): State<BackendsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((route, backend)): Path<(String, String)>,
    Json(body): Json<BackendBody>,
) -> Response {
    let reg = match route_of(&st, &route).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if let Err(e) = super::validators::validate_name(&backend) {
        return registration_error_response(&e);
    }
    let egress = body.egress.unwrap_or_default();
    if let Err(e) =
        super::protocol::validate(Protocol::Http, None, reg.kind, egress, &body.upstream, None)
    {
        return registration_error_response(&e);
    }
    if let Err(e) = super::upstream_ca::validate(
        body.upstream_ca_pem.as_deref(),
        &body.upstream,
        Protocol::Http,
    ) {
        return registration_error_response(&e);
    }
    if oauth(&body.auth) {
        return backend_error(&BackendError::AuthUnsupported);
    }
    if let Err(msg) = body.auth.validate_op_reference() {
        return registration_error_response(&RegistrationError::InvalidMetadata(msg));
    }
    let repo = BackendRepository::new(st.regs.repo.pool.clone());
    match repo.active_backend(&route).await {
        Ok(a) if a == backend => return backend_error(&BackendError::ActiveBackend),
        Ok(_) => {}
        Err(e) => return backend_error(&e),
    }
    let b = RouteBackend {
        route,
        name: backend,
        upstream: body.upstream,
        egress,
        upstream_ca_pem: body.upstream_ca_pem,
        auth: body.auth,
        created_at: 0,
        updated_at: 0,
    };
    if let Err(e) = repo.put(&b).await {
        return backend_error(&e);
    }
    match repo.get(&b.route, &b.name).await {
        Ok(Some(saved)) => {
            let details = json!({
                "route": saved.route,
                "backend": saved.name,
                "upstream": saved.upstream,
                "egress": super::backends::egress_str(saved.egress),
                "upstream_ca_sha256": ca_sha256(saved.upstream_ca_pem.as_deref()),
                "auth_kind": auth_kind(&saved.auth),
            });
            audit(&st, &op, &saved.route, "route_backend_put", details).await;
            Json(view(&saved)).into_response()
        }
        Ok(None) => backend_error(&BackendError::NotFound),
        Err(e) => backend_error(&e),
    }
}

async fn delete(
    State(st): State<BackendsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((route, backend)): Path<(String, String)>,
) -> Response {
    if let Err(r) = route_of(&st, &route).await {
        return r;
    }
    let repo = BackendRepository::new(st.regs.repo.pool.clone());
    match repo.active_backend(&route).await {
        Ok(a) if a == backend => return backend_error(&BackendError::ActiveBackend),
        Ok(_) => {}
        Err(e) => return backend_error(&e),
    }
    match repo.delete(&route, &backend).await {
        Ok(true) => {
            let details = json!({ "route": route, "backend": backend });
            audit(&st, &op, &route, "route_backend_deleted", details).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => backend_error(&BackendError::NotFound),
        Err(e) => backend_error(&e),
    }
}

async fn switch(
    State(st): State<BackendsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path(route): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SwitchBody>,
) -> Response {
    let Some(expected) = headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().trim_matches('"').parse::<i64>())
    else {
        return error(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "if_match_required",
        );
    };
    let Ok(expected) = expected else {
        return backend_error(&BackendError::RevisionConflict);
    };
    let before = match route_of(&st, &route).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    let repo = BackendRepository::new(st.regs.repo.pool.clone());
    let out = match repo.switch(&route, &body.backend, expected).await {
        Ok(o) => o,
        Err(e) => return backend_error(&e),
    };
    let after = match st.regs.repo.get(&route).await {
        Ok(Some(r)) => r,
        _ => before.clone(),
    };
    // Persisted; admission fails closed (503) until the catalog matches.
    let activation = if st.regs.refresh_runtime().await.is_ok() {
        "active"
    } else {
        "pending"
    };
    let details = json!({
        "route": out.route,
        "from": out.from,
        "to": out.to,
        "bindings_stashed": out.bindings_stashed,
        "bindings_restored": out.bindings_restored,
        "revision": out.revision,
        "profile_before": before.effective_profile().as_str(),
        "profile_after": after.effective_profile().as_str(),
        "upstream_before": before.upstream,
        "upstream_after": after.upstream,
        "egress_before": super::backends::egress_str(before.egress),
        "egress_after": super::backends::egress_str(after.egress),
        "upstream_ca_sha256_before": ca_sha256(before.upstream_ca_pem.as_deref()),
        "upstream_ca_sha256_after": ca_sha256(after.upstream_ca_pem.as_deref()),
    });
    audit(&st, &op, &route, "route_backend_switched", details.clone()).await;
    let mut resp = details;
    resp["activation"] = activation.into();
    Json(resp).into_response()
}
