//! Admin Unix domain socket listener (T2.13).
//! C-2 (SPEC §4.2.4). Mode 0660, owner+group `locksmith` (configurable).
//! Two routers: /admin/agent/* (agent-self-service) and /admin/operator/*
//! (cross-cutting).

use crate::admin::AdminService;
use crate::admin::service::AdminError;
use crate::agent_listener::PeerCertDer;
use crate::auth_v2::{
    AgentAuthenticator, AuthError, BearerAuthenticator, OperatorAuthenticator, OperatorIdentity,
};
use crate::config::AuthMode;
use crate::mtls::MtlsValidator;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{any, get, post};
use axum::{Router, body::Body};
use serde::Deserialize;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::Path as FsPath;
use std::sync::Arc;
use tokio::net::UnixListener;
use tracing::{info, warn};

/// Per-listener mTLS context for the operator router (#83). When `None`
/// on a `UdsState`, the operator middleware enforces bearer-only auth
/// (M0..M5 default — UDS path always uses this). When `Some`, the
/// listener is admin HTTPS in mtls/both mode and the middleware extracts
/// the peer cert injected by `agent_listener::bind_and_serve_mtls`.
#[derive(Clone)]
pub struct OperatorMtlsContext {
    pub auth_mode: AuthMode,
    pub validator: Arc<MtlsValidator>,
}

#[derive(Clone)]
pub struct UdsState {
    pub admin: Arc<AdminService>,
    pub agent_auth: Arc<BearerAuthenticator>,
    pub operator_auth: Arc<OperatorAuthenticator>,
    /// `None` ⇒ bearer-only operator path (UDS always; HTTPS in M4
    /// `auth_mode=bearer` mode). `Some(ctx)` ⇒ admin HTTPS with mTLS.
    pub operator_mtls: Option<OperatorMtlsContext>,
    /// Phase E.3 — registrations repo for `/admin/operator/{tools,models,
    /// infra}/<name>` routes. `None` for M0/M1 deployments without admin
    /// substrate; the registrations routes are then absent from the
    /// router entirely.
    pub registrations: Option<Arc<crate::registrations::RegistrationRepository>>,
    /// Phase E.6 — agent router's in-memory `Catalog` cache. Threaded
    /// through so admin write handlers refresh it after upsert/delete/
    /// enable. `None` keeps the route mounted but skips refresh; the
    /// proxy hot path then sees stale state until next daemon start.
    pub catalog: Option<Arc<arc_swap::ArcSwap<crate::registrations::Catalog>>>,
    /// Phase E.6 — agent router's `ResolvedCreds` map. Threaded through
    /// so admin write handlers can resolve any newly-referenced env
    /// vars after a registration's auth shape changes.
    pub resolved_creds: Option<Arc<arc_swap::ArcSwap<crate::secret::ResolvedCreds>>>,
    /// Phase F.4 — OAuth admin state. `None` for deployments that
    /// haven't set `LOCKSMITH_OAUTH_SEALING_KEY` (the daemon then
    /// boots without OAuth support; the routes below 404 cleanly).
    pub oauth: Option<crate::oauth::OauthAdminState>,
}

/// Build the Phase E registrations sub-router. Mounts at the operator
/// nest point (`/admin/operator`); routes look like
/// `/admin/operator/tools/<name>`, `/admin/operator/models/<name>`,
/// `/admin/operator/infra/<name>`, plus list endpoints and an
/// `enable` action to un-disable a previously-disabled seed row.
///
/// Phase E.6 — `catalog` and `resolved_creds` are optional refs into
/// the agent router's runtime state. When `Some`, admin writes refresh
/// both so the proxy hot path picks up changes without a daemon
/// restart. When `None` (legacy / non-daemon paths), admin writes
/// still hit the repo but no in-memory cache exists to invalidate.
fn build_registrations_admin_router(
    repo: Arc<crate::registrations::RegistrationRepository>,
    catalog: Option<Arc<arc_swap::ArcSwap<crate::registrations::Catalog>>>,
    resolved_creds: Option<Arc<arc_swap::ArcSwap<crate::secret::ResolvedCreds>>>,
) -> Router {
    use crate::registrations::api;
    let st = api::AdminRegistrationsState {
        repo,
        catalog,
        resolved_creds,
    };
    Router::new()
        .route("/tools", get(api::op_list_tools))
        .route(
            "/tools/{name}",
            get(api::op_get_tool)
                .put(api::op_put_tool)
                .delete(api::op_delete_tool),
        )
        .route("/tools/{name}/enable", post(api::op_enable_tool))
        .route("/models", get(api::op_list_models))
        .route(
            "/models/{name}",
            get(api::op_get_model)
                .put(api::op_put_model)
                .delete(api::op_delete_model),
        )
        .route("/models/{name}/enable", post(api::op_enable_model))
        .route("/infra", get(api::op_list_infra))
        .route(
            "/infra/{name}",
            get(api::op_get_infra)
                .put(api::op_put_infra)
                .delete(api::op_delete_infra),
        )
        .route("/infra/{name}/enable", post(api::op_enable_infra))
        .with_state(st)
}

/// Phase F.4 — OAuth admin sub-router. Mounts under operator nest.
/// Routes: `POST /oauth/<name>/bootstrap`, `GET /oauth/<name>`,
/// `DELETE /oauth/<name>`. Only mounted when `LOCKSMITH_OAUTH_SEALING_KEY`
/// is set (`UdsState.oauth = Some(_)`).
fn build_oauth_admin_router(state: crate::oauth::OauthAdminState) -> Router {
    use crate::oauth::admin;
    Router::new()
        .route(
            "/oauth/{name}",
            get(admin::op_oauth_status).delete(admin::op_oauth_revoke),
        )
        .route("/oauth/{name}/bootstrap", post(admin::op_oauth_bootstrap))
        .with_state(state)
}

/// Build the admin router. Public for testing — production wiring uses
/// `bind_and_serve` below.
pub fn build_router(state: UdsState) -> Router {
    // Agent self-service routes that DO require an agent token.
    let agent_authed_routes = Router::new()
        .route("/status", get(handle_status))
        .route("/rotate", post(handle_rotate))
        .route("/deregister", post(handle_deregister))
        .route("/tools", get(handle_agent_tools))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            agent_auth_middleware,
        ));

    // /register is bootstrap-token-authed *inside* the handler (D-10);
    // no agent-auth middleware applies. Sits in its own router so it
    // doesn't inherit the agent-auth layer above.
    let agent_register_routes = Router::new().route("/register", any(handle_register));

    let agent_routes = Router::new()
        .merge(agent_authed_routes)
        .merge(agent_register_routes)
        .with_state(state.clone());

    let operator_existing = Router::new()
        .route("/agents", get(op_list_agents).post(op_create_agent))
        .route(
            "/agents/{public_id}",
            get(op_get_agent).patch(op_modify_agent),
        )
        .route("/agents/{public_id}/revoke", post(op_revoke_agent))
        .route(
            "/agents/{public_id}/cert_identity",
            axum::routing::patch(op_set_agent_cert_identity),
        )
        .route(
            "/bootstrap_tokens",
            get(op_list_bootstrap).post(op_mint_bootstrap),
        )
        .route(
            "/bootstrap_tokens/{public_id}/revoke",
            post(op_revoke_bootstrap),
        )
        .route("/tools-legacy", get(op_list_tools))
        .route("/audit", get(op_query_audit))
        .with_state(state.clone());

    // Phase E.3 registrations sub-router (only mounted when the repo is
    // wired). Carries its own `AdminRegistrationsState`, merges in as a
    // `Router<()>` after `.with_state(...)`. The outer
    // `operator_auth_middleware` layer applies uniformly across both
    // sub-routers.
    let operator_with_registrations = match state.registrations.clone() {
        Some(repo) => operator_existing.merge(build_registrations_admin_router(
            repo,
            state.catalog.clone(),
            state.resolved_creds.clone(),
        )),
        None => operator_existing,
    };
    let operator_routes = match state.oauth.clone() {
        Some(oauth_state) => {
            operator_with_registrations.merge(build_oauth_admin_router(oauth_state))
        }
        None => operator_with_registrations,
    }
    .layer(axum::middleware::from_fn_with_state(
        state.clone(),
        operator_auth_middleware,
    ));

    Router::new()
        .nest("/admin/agent", agent_routes)
        .nest("/admin/operator", operator_routes)
}

/// Bind a Unix domain socket at `path` with mode `0o660` and serve the
/// admin router. Removes a stale socket file from a previous unclean
/// shutdown if found.
pub async fn bind_and_serve(
    path: &FsPath,
    state: UdsState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    if path.exists() {
        // Sanity check: it's a socket, no process is bound (best-effort).
        let meta = std::fs::metadata(path)?;
        if std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()) {
            std::fs::remove_file(path)?;
            warn!(path = %path.display(), "removed stale admin socket from prior run");
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    info!(socket = %path.display(), "admin UDS listener bound");

    let app = build_router(state);
    let make_service = app.into_make_service();
    axum::serve(listener, make_service)
        .with_graceful_shutdown(shutdown)
        .await
}

// ─── Middleware ────────────────────────────────────────────────────

async fn agent_auth_middleware(
    State(state): State<UdsState>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let header = match req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h.to_string(),
        None => return error_response(AuthError::MissingCredential),
    };
    match state.agent_auth.authenticate_bearer(&header).await {
        Ok(identity) => {
            req.extensions_mut().insert(identity);
            next.run(req).await
        }
        Err(e) => error_response(e),
    }
}

async fn operator_auth_middleware(
    State(state): State<UdsState>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // mTLS-bound operator path (#83 / T6.7 wire-side closure). Active
    // only when the listener was wired with an mtls context; the UDS
    // path leaves this as None and falls through to bearer-only.
    if let Some(mtls) = state.operator_mtls.clone() {
        let peer = req.extensions().get::<PeerCertDer>().cloned();
        let cert_der = peer.as_ref().and_then(|p| p.0.clone());
        match (mtls.auth_mode, cert_der) {
            (AuthMode::Mtls, None) => return error_response(AuthError::MissingCredential),
            (AuthMode::Mtls, Some(der)) | (AuthMode::Both, Some(der)) => {
                let identity = match mtls.validator.validate(&der) {
                    Ok(id) => id,
                    Err(_) => return error_response(AuthError::InvalidCredential),
                };
                match state
                    .operator_auth
                    .authenticate_cert_identity(&identity.value)
                    .await
                {
                    Ok(op) => {
                        req.extensions_mut().insert(op);
                        return next.run(req).await;
                    }
                    Err(e) => return error_response(e),
                }
            }
            // Both + no cert ⇒ fall through to bearer.
            (AuthMode::Both, None) => {}
            // Bearer is the listener-shape default; treated identically
            // to "no operator_mtls context" — fall through.
            (AuthMode::Bearer, _) => {}
        }
    }

    let header = match req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h.to_string(),
        None => return error_response(AuthError::MissingCredential),
    };
    match state.operator_auth.authenticate_bearer(&header).await {
        Ok(identity) => {
            req.extensions_mut().insert(identity);
            next.run(req).await
        }
        Err(e) => error_response(e),
    }
}

fn error_response(e: AuthError) -> Response {
    let body = json!({
        "error": {
            "code": e.code(),
            "message": e.to_string(),
        }
    });
    let status = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(body)).into_response()
}

fn admin_err_response(e: AdminError) -> Response {
    let (status, code) = match &e {
        AdminError::InvalidBootstrap => (StatusCode::UNAUTHORIZED, "invalid_credential"),
        AdminError::AgentNameConflict => (StatusCode::CONFLICT, "agent_name_conflict"),
        AdminError::RotationInProgress => (StatusCode::CONFLICT, "rotation_in_progress"),
        AdminError::AgentNotFound => (StatusCode::NOT_FOUND, "agent_not_found"),
        AdminError::NotAuthorized => (StatusCode::FORBIDDEN, "forbidden"),
        AdminError::Backend(_) => (StatusCode::INTERNAL_SERVER_ERROR, "backend_error"),
    };
    (
        status,
        Json(json!({
            "error": { "code": code, "message": e.to_string() }
        })),
    )
        .into_response()
}

// ─── Agent handlers ────────────────────────────────────────────────

async fn handle_register(
    State(state): State<UdsState>,
    Json(input): Json<crate::admin::service::RegisterInput>,
) -> Response {
    match state.admin.register_agent(input).await {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(e) => admin_err_response(e),
    }
}

async fn handle_status(
    State(state): State<UdsState>,
    Extension(agent): Extension<crate::auth_v2::AgentIdentity>,
) -> Response {
    match state.admin.get_agent_status(&agent).await {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(e) => admin_err_response(e),
    }
}

#[derive(Deserialize)]
struct RotateInput {
    current_secret: String,
}

async fn handle_rotate(
    State(state): State<UdsState>,
    Extension(agent): Extension<crate::auth_v2::AgentIdentity>,
    Json(input): Json<RotateInput>,
) -> Response {
    let secret = secrecy::SecretString::from(input.current_secret);
    match state.admin.rotate_agent(&agent, &secret).await {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(e) => admin_err_response(e),
    }
}

async fn handle_deregister(
    State(state): State<UdsState>,
    Extension(agent): Extension<crate::auth_v2::AgentIdentity>,
) -> Response {
    match state.admin.deregister_agent(&agent).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => admin_err_response(e),
    }
}

async fn handle_agent_tools(
    State(state): State<UdsState>,
    Extension(agent): Extension<crate::auth_v2::AgentIdentity>,
) -> Response {
    match state.admin.list_tools_for_agent(&agent).await {
        Ok(tools) => (StatusCode::OK, Json(json!({ "tools": tools }))).into_response(),
        Err(e) => admin_err_response(e),
    }
}

// ─── Operator handlers ─────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct ListAgentsQuery {
    #[serde(default)]
    include_revoked: bool,
}

async fn op_list_agents(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Query(q): Query<ListAgentsQuery>,
) -> Response {
    match state.admin.list_agents(&op, q.include_revoked).await {
        Ok(agents) => {
            let agents: Vec<_> = agents
                .into_iter()
                .map(|a| {
                    json!({
                        "public_id": a.public_id,
                        "name": a.name,
                        "description": a.description,
                        "tool_allowlist": a.tool_allowlist,
                        "tool_denylist": a.tool_denylist,
                        "registered_at": a.registered_at,
                        "last_used_at": a.last_used_at,
                        "expires_at": a.expires_at,
                        "revoked_at": a.revoked_at,
                        "cert_identity": a.cert_identity,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "agents": agents }))).into_response()
        }
        Err(e) => admin_err_response(e),
    }
}

async fn op_get_agent(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> Response {
    match state.admin.get_agent(&op, &id).await {
        Ok(a) => (
            StatusCode::OK,
            Json(json!({
                "public_id": a.public_id,
                "name": a.name,
                "description": a.description,
                "tool_allowlist": a.tool_allowlist,
                "tool_denylist": a.tool_denylist,
                "registered_at": a.registered_at,
                "last_used_at": a.last_used_at,
                "expires_at": a.expires_at,
                "revoked_at": a.revoked_at,
                "cert_identity": a.cert_identity,
            })),
        )
            .into_response(),
        Err(e) => admin_err_response(e),
    }
}

async fn op_create_agent(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Json(input): Json<crate::admin::service::CreateAgentInput>,
) -> Response {
    match state.admin.create_agent_as_operator(&op, input).await {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(e) => admin_err_response(e),
    }
}

async fn op_modify_agent(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path(id): Path<String>,
    Json(input): Json<crate::admin::service::ModifyAgentInput>,
) -> Response {
    match state.admin.modify_agent(&op, &id, input).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => admin_err_response(e),
    }
}

async fn op_revoke_agent(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> Response {
    match state.admin.revoke_agent(&op, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => admin_err_response(e),
    }
}

#[derive(Deserialize)]
struct SetCertIdentityInput {
    /// `Some(s)` ⇒ bind cert_identity to `s`; `None` ⇒ clear (#79).
    #[serde(default)]
    cert_identity: Option<String>,
}

async fn op_set_agent_cert_identity(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path(id): Path<String>,
    Json(input): Json<SetCertIdentityInput>,
) -> Response {
    match state
        .admin
        .set_agent_cert_identity(&op, &id, input.cert_identity)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => admin_err_response(e),
    }
}

async fn op_mint_bootstrap(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Json(input): Json<crate::admin::service::MintBootstrapInput>,
) -> Response {
    match state.admin.mint_bootstrap_token(&op, input).await {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(e) => admin_err_response(e),
    }
}

async fn op_list_bootstrap(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
) -> Response {
    match state.admin.list_bootstrap_tokens(&op).await {
        Ok(tokens) => {
            let tokens: Vec<_> = tokens
                .into_iter()
                .map(|t| {
                    json!({
                        "public_id": t.public_id,
                        "scope": t.scope,
                        "created_by": t.created_by,
                        "created_at": t.created_at,
                        "expires_at": t.expires_at,
                        "used_at": t.used_at,
                        "used_by_agent_id": t.used_by_agent_id,
                        "revoked_at": t.revoked_at,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "tokens": tokens }))).into_response()
        }
        Err(e) => admin_err_response(e),
    }
}

async fn op_revoke_bootstrap(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> Response {
    match state.admin.revoke_bootstrap_token(&op, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => admin_err_response(e),
    }
}

async fn op_list_tools(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
) -> Response {
    match state.admin.list_tools_for_operator(&op).await {
        Ok(tools) => (StatusCode::OK, Json(json!({ "tools": tools }))).into_response(),
        Err(e) => admin_err_response(e),
    }
}

#[derive(Deserialize, Default)]
struct AuditQueryParams {
    since_ms: Option<i64>,
    until_ms: Option<i64>,
    agent: Option<String>,
    tool: Option<String>,
    event_class: Option<String>,
    decision: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn op_query_audit(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Query(q): Query<AuditQueryParams>,
) -> Response {
    use crate::repo::audit::{AuditFilter, AuditPage, Decision, EventClass};

    let event_class = match q.event_class.as_deref() {
        Some("proxy") => Some(EventClass::Proxy),
        Some("operator") => Some(EventClass::Operator),
        Some("security") => Some(EventClass::Security),
        Some(other) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": { "code": "invalid_event_class", "message": format!("unknown event_class: {other}") }
                })),
            )
                .into_response();
        }
        None => None,
    };
    let decision = match q.decision.as_deref() {
        Some("allowed") => Some(Decision::Allowed),
        Some("denied") => Some(Decision::Denied),
        Some("error") => Some(Decision::Error),
        Some(other) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": { "code": "invalid_decision", "message": format!("unknown decision: {other}") }
                })),
            )
                .into_response();
        }
        None => None,
    };
    let filter = AuditFilter {
        since_ms: q.since_ms,
        until_ms: q.until_ms,
        agent_public_id: q.agent,
        tool: q.tool,
        event_class,
        decision,
    };
    let page = AuditPage {
        limit: q.limit.unwrap_or(100),
        offset: q.offset.unwrap_or(0),
    };
    match state.admin.query_audit(&op, filter, page).await {
        Ok(rows) => {
            let rows: Vec<_> = rows
                .into_iter()
                .map(|e| {
                    json!({
                        "ts_ms": e.ts_ms,
                        "event_class": e.event_class.as_str(),
                        "event": e.event,
                        "agent_public_id": e.agent_public_id,
                        "agent_name": e.agent_name,
                        "operator_name": e.operator_name,
                        "tool": e.tool,
                        "upstream_host": e.upstream_host,
                        "method": e.method,
                        "path": e.path,
                        "status": e.status,
                        "latency_ms": e.latency_ms,
                        "decision": e.decision.as_str(),
                        "auth_method": e.auth_method,
                        "origin_ip": e.origin_ip,
                        "details": e.details,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "events": rows }))).into_response()
        }
        Err(e) => admin_err_response(e),
    }
}

// Avoid an unused-import warning in clippy when only headers are needed
// elsewhere — keep the import explicit for future expansion.
#[allow(dead_code)]
fn _unused(_h: &HeaderMap, _b: &Body) {}
