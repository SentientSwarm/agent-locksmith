//! Daemon runtime: binds the agent TCP listener and (optionally) the
//! admin Unix domain socket listener, then awaits shutdown for both
//! within the configured drain window.
//!
//! Extracted from `main.rs` so the runtime is callable from integration
//! tests with a configurable shutdown trigger and so the binary entry
//! point stays tiny.
//!
//! The admin substrate (UDS + AdminService + repos + operator auth) is
//! only constructed when `listen.admin_socket` is configured. M0/M1
//! configs without admin_socket continue to run with only the TCP agent
//! listener bound — preserving backward compat.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::admin::{AdminService, uds::UdsState};
use crate::app::{build_app_with_audit, build_app_with_shared_config};
use crate::auth_v2::{BearerAuthenticator, OperatorAuthenticator};
use crate::config::AppConfig;
use crate::migrations;
use crate::repo::{AgentRepository, AuditRepository, BootstrapTokenRepository};
use crate::shutdown::ShutdownCoordinator;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("admin substrate misconfigured: {0}")]
    AdminConfig(String),
    #[error("database: {0}")]
    Database(#[from] migrations::MigrationError),
    #[error("operator credentials: {0}")]
    OperatorCreds(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("server: {0}")]
    Server(String),
}

/// Run the daemon to completion. Returns when both listeners shut down
/// (or the drain window expires).
pub async fn run(config: AppConfig, coord: ShutdownCoordinator) -> Result<(), DaemonError> {
    let admin_socket_path = config.listen.admin_socket.as_ref().map(|s| s.path.clone());
    let admin_enabled = admin_socket_path.is_some();
    if admin_enabled {
        if config.database.is_none() {
            return Err(DaemonError::AdminConfig(
                "listen.admin_socket is set but `database.path` is missing".into(),
            ));
        }
        if config.operator_credentials_path.is_none() {
            return Err(DaemonError::AdminConfig(
                "listen.admin_socket is set but `operator_credentials_path` is missing".into(),
            ));
        }
    }

    let addr = SocketAddr::new(
        config.listen.host.parse().unwrap_or([127, 0, 0, 1].into()),
        config.listen.port,
    );

    // Wrap config in shared ArcSwap. Both the agent router (via
    // build_app_with_shared_config) and the AdminService observe this
    // same snapshot, so hot reload (T1.5) is unified across both
    // surfaces.
    let shared_config: Arc<ArcSwap<AppConfig>> = Arc::new(ArcSwap::from_pointee(config));

    // Admin substrate (DB + auth + service) — built before listener
    // binding so a misconfig fails fast. The same pool feeds the audit
    // repository handed to the agent router, so proxy writes share one
    // SQLite connection pool with admin reads.
    let (admin_state, audit_for_proxy) = if admin_enabled {
        let setup = build_admin_substrate(shared_config.clone()).await?;
        (Some(setup.uds_state), Some(setup.audit))
    } else {
        (None, None)
    };

    // Agent listener.
    let agent_router = if let Some(audit) = audit_for_proxy {
        build_app_with_audit(shared_config, Some(audit))
    } else {
        build_app_with_shared_config(shared_config)
    };
    let listener = TcpListener::bind(addr).await?;
    info!("agent listener bound on {addr}");
    let agent_shutdown = coord.shutdown_signal();
    let agent_task = tokio::spawn(async move {
        axum::serve(listener, agent_router)
            .with_graceful_shutdown(agent_shutdown)
            .await
    });

    // Admin UDS listener (when configured).
    let admin_task = if let Some(state) = admin_state {
        let path = admin_socket_path.expect("checked above");
        let admin_shutdown = coord.shutdown_signal();
        Some(tokio::spawn(async move {
            crate::admin::uds::bind_and_serve(&path, state, admin_shutdown).await
        }))
    } else {
        None
    };

    let drain = async {
        if let Some(admin) = admin_task {
            let (a, b) = tokio::join!(agent_task, admin);
            (Some(a), Some(b))
        } else {
            (Some(agent_task.await), None)
        }
    };

    match coord.drain_or_timeout(drain).await {
        Ok((agent_res, admin_res)) => {
            if let Some(Ok(Err(e))) = agent_res {
                return Err(DaemonError::Server(format!("agent listener: {e}")));
            }
            if let Some(Ok(Err(e))) = admin_res {
                return Err(DaemonError::Server(format!("admin listener: {e}")));
            }
            info!("clean shutdown complete");
            Ok(())
        }
        Err(_) => {
            warn!("drain window exceeded; tasks dropped");
            Ok(())
        }
    }
}

/// Bundle of the admin substrate that the daemon runtime hands out:
/// the UDS router state plus a clone of the AuditRepository so the
/// proxy hot path can write to the same audit table.
struct AdminSetup {
    uds_state: UdsState,
    audit: AuditRepository,
}

async fn build_admin_substrate(config: Arc<ArcSwap<AppConfig>>) -> Result<AdminSetup, DaemonError> {
    let snapshot = config.load();
    let db_path = snapshot
        .database
        .as_ref()
        .expect("checked in run()")
        .path
        .clone();
    let ops_path = snapshot
        .operator_credentials_path
        .as_ref()
        .expect("checked in run()")
        .clone();
    drop(snapshot);

    if let Some(parent) = db_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let pool = migrations::open_and_migrate(&db_path).await?;
    info!(database = %db_path.display(), "database opened and migrated");

    let agents = AgentRepository::new(pool.clone());
    let bootstrap = BootstrapTokenRepository::new(pool.clone());
    let audit = AuditRepository::new(pool);

    let agent_auth = BearerAuthenticator::new(agents.clone())
        .map_err(|e| DaemonError::AdminConfig(format!("agent auth: {e}")))?;
    let operator_auth = OperatorAuthenticator::load(&ops_path)
        .map_err(|e| DaemonError::OperatorCreds(e.to_string()))?;
    info!(operator_credentials = %ops_path.display(), "operator authenticator loaded");

    let admin = AdminService::with_audit(agents, bootstrap, config, Some(audit.clone()));

    Ok(AdminSetup {
        uds_state: UdsState {
            admin: Arc::new(admin),
            agent_auth: Arc::new(agent_auth),
            operator_auth: Arc::new(operator_auth),
        },
        audit,
    })
}

/// Convenience for tests: pre-construct a coordinator with the given
/// drain window, spawn the runtime, and return the coordinator + handle
/// so the test can `.trigger()` and `.await` cleanly.
pub async fn run_with_drain_window(
    config: AppConfig,
    drain: Duration,
) -> (
    ShutdownCoordinator,
    tokio::task::JoinHandle<Result<(), DaemonError>>,
) {
    let coord = ShutdownCoordinator::new(drain);
    let coord_clone = coord.clone();
    let handle = tokio::spawn(async move { run(config, coord_clone).await });
    (coord, handle)
}
