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
use crate::audit_sink::{JsonlSink, JsonlSinkConfig};
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
    let (admin_state, audit_for_proxy, audit_for_sweeper) = if admin_enabled {
        let setup = build_admin_substrate(shared_config.clone()).await?;
        (
            Some(setup.uds_state),
            Some(setup.audit.clone()),
            Some(setup.audit),
        )
    } else {
        (None, None, None)
    };

    // Audit retention sweeper (T3.5). Runs only when admin substrate is
    // up — otherwise there's no audit to sweep. Defaults to
    // 90 days / hourly when `audit:` is absent from config.
    let sweeper_task = audit_for_sweeper.map(|audit| {
        let snapshot = shared_config.load();
        let cfg = snapshot.audit.as_ref().cloned().unwrap_or_default();
        drop(snapshot);
        let shutdown = coord.shutdown_signal();
        tokio::spawn(audit_retention_sweeper(audit, cfg, shutdown))
    });

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
        let (a, b) = if let Some(admin) = admin_task {
            let (a, b) = tokio::join!(agent_task, admin);
            (Some(a), Some(b))
        } else {
            (Some(agent_task.await), None)
        };
        // Sweeper exits on its own when the shutdown signal fires; we
        // join it here so a slow tick can finish cleanly within the
        // drain window. Errors are logged but never poisoned shutdown.
        if let Some(s) = sweeper_task {
            let _ = s.await;
        }
        (a, b)
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

/// Periodically sweep audit rows older than `now - retention_days`.
/// Exits cleanly when the shutdown future resolves.
///
/// Verification gate (T3.5):
/// - Cutoff is `now_ms - retention_days * MS_PER_DAY` — single integer
///   path, no floats.
/// - SELECT-then-DELETE is unnecessary; the bounded `DELETE WHERE ts <
///   ?` only touches the audit table.
/// - tokio::select between `tick()` and the shutdown future ensures we
///   never start a fresh DELETE after shutdown was signalled; we
///   complete the in-flight one and exit.
async fn audit_retention_sweeper(
    audit: AuditRepository,
    cfg: crate::config::AuditConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    const MS_PER_DAY: i64 = 24 * 60 * 60 * 1_000;
    let interval = Duration::from_secs(cfg.sweep_interval_seconds.max(1));
    let mut ticker = tokio::time::interval(interval);
    // We want immediate first sweep on startup so freshly-rotated
    // databases drop ancient rows on boot.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("audit sweeper: shutdown signal observed; exiting cleanly");
                return;
            }
            _ = ticker.tick() => {
                let cutoff = now_ms() - i64::from(cfg.retention_days) * MS_PER_DAY;
                match audit.sweep_older_than(cutoff).await {
                    Ok(0) => {}
                    Ok(n) => info!(deleted = n, retention_days = cfg.retention_days, "audit retention sweep deleted rows"),
                    Err(e) => warn!(error = %e, "audit retention sweep failed; will retry next interval"),
                }
            }
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
    let mut audit = AuditRepository::new(pool);

    // JSONL mirror sink — optional, opens at startup so misconfig
    // (unwritable path) surfaces here rather than at first audit
    // insert. Wraps in Arc so cloned AuditRepository handles share it.
    let snapshot = config.load();
    if let Some(audit_cfg) = snapshot.audit.as_ref()
        && let Some(jsonl_path) = audit_cfg.jsonl_path.as_ref()
    {
        let sink_cfg = JsonlSinkConfig {
            path: jsonl_path.clone(),
            max_bytes: audit_cfg.jsonl_max_bytes,
            keep_files: audit_cfg.jsonl_keep_files,
        };
        match JsonlSink::new(sink_cfg) {
            Ok(sink) => {
                info!(path = %jsonl_path.display(), "audit JSONL sink opened");
                audit = audit.with_sink(std::sync::Arc::new(sink));
            }
            Err(e) => {
                return Err(DaemonError::AdminConfig(format!(
                    "audit jsonl sink {}: {e}",
                    jsonl_path.display()
                )));
            }
        }
    }
    drop(snapshot);

    let agent_auth = BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone()))
        .map_err(|e| DaemonError::AdminConfig(format!("agent auth: {e}")))?;
    let operator_auth = OperatorAuthenticator::load_with_audit(&ops_path, Some(audit.clone()))
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
