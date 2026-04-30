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
//! Off-by-default. The daemon only binds when
//! `listen.bootstrap_only.enabled = true` (see config.rs).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use axum_server::Handle;
use serde_json::json;
use tracing::{info, warn};

use super::AdminService;
use super::https::load_tls_config;

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

/// Bind a TLS-terminated bootstrap-only listener. Same TLS-load
/// fail-fast contract as `admin::https::bind_and_serve` (T4.2).
pub async fn bind_and_serve(
    addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    state: BootstrapState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let tls = load_tls_config(cert_path, key_path).await?;
    let app = build_router(state);

    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        info!("bootstrap-only listener: shutdown signal observed; draining");
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
    });

    info!(addr = %addr, cert = %cert_path.display(), "bootstrap-only listener bound");
    let result = axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(app.into_make_service())
        .await;
    if let Err(e) = &result {
        warn!(error = %e, "bootstrap-only listener exited with error");
    }
    result
}
