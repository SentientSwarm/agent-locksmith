//! T6.8 — bootstrap-only listener (C-4, SPEC §4.2.6).
//!
//! TLS-terminated TCP listener that exposes ONLY
//! `POST /admin/agent/register`. Designed for mtls-only deployments
//! where the agent listener requires a client cert but onboarding a
//! fresh agent (which has no cert yet) needs an out-of-band path.
//!
//! Per D-10, bootstrap-token register stands on its own — no bearer
//! header, no client cert. The bootstrap_token IS the credential.
//! Operators lock down the network reach of this listener via firewall
//! / Tailscale / localhost-only binding.
//!
//! Off-by-default. The daemon binds it only when
//! `listen.bootstrap_only.enabled = true` (see config.rs), and only with
//! the admin substrate (`listen.admin_socket`), whose `AdminService`
//! verifies the bootstrap token.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use serde_json::json;
use tracing::{info, warn};

use super::AdminService;

/// State for the bootstrap-only router. Just the AdminService — no
/// auth state, no audit-aware authenticators (the register handler
/// does its own bootstrap-token verification through AdminService).
#[derive(Clone)]
pub struct BootstrapState {
    pub admin: Arc<AdminService>,
}

pub fn build_router(state: BootstrapState) -> Router {
    Router::new()
        .route("/admin/agent/register", post(handle_register))
        .layer(axum::middleware::map_response(
            crate::admin::error_envelope::fill_error_type,
        ))
        .with_state(state)
}

async fn handle_register(
    State(state): State<BootstrapState>,
    Json(input): Json<crate::admin::service::RegisterInput>,
) -> Response {
    match state.admin.register_agent(input).await {
        Ok(out) => (StatusCode::OK, Json(out)).into_response(),
        Err(e) => {
            // Map AdminError to a structured response. We deliberately
            // don't pull in admin::uds::admin_err_response to keep
            // this listener self-contained.
            let (status, code) = match &e {
                crate::admin::service::AdminError::InvalidBootstrap => {
                    (StatusCode::UNAUTHORIZED, "invalid_credential")
                }
                crate::admin::service::AdminError::AgentNameConflict => {
                    (StatusCode::CONFLICT, "agent_name_conflict")
                }
                crate::admin::service::AdminError::AgentNotFound => {
                    (StatusCode::NOT_FOUND, "agent_not_found")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "backend_error"),
            };
            (
                status,
                Json(json!({"error": {"code": code, "message": e.to_string()}})),
            )
                .into_response()
        }
    }
}

/// Serve the bootstrap-only router on a listener bound by
/// `admin::https::bind`. The daemon loads `tls` before spawning, so a bad
/// cert or key fails startup rather than the running listener (T4.2).
pub async fn serve(
    listener: std::net::TcpListener,
    tls: RustlsConfig,
    state: BootstrapState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let addr = listener.local_addr()?;
    if let Some(rt) = state.admin.native_authority() {
        rt.listeners.bound("bootstrap", addr);
    }
    let app = build_router(state);

    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        info!("bootstrap-only listener: shutdown signal observed; draining");
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
    });

    info!(addr = %addr, "bootstrap-only listener bound");
    let result = axum_server::from_tcp_rustls(listener, tls)
        .handle(handle)
        .serve(app.into_make_service())
        .await;
    if let Err(e) = &result {
        warn!(error = %e, "bootstrap-only listener exited with error");
    }
    result
}
