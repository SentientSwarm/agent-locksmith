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

mod oauth;
mod state_lock;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use crate::admin::{AdminService, uds::UdsState};
use crate::audit_sink::{JsonlSink, JsonlSinkConfig};
use crate::auth_v2::{BearerAuthenticator, OperatorAuthenticator};
use crate::config::AppConfig;
use crate::migrations;
use crate::repo::{AgentRepository, AuditRepository, BootstrapTokenRepository};
use crate::secret::{FileSealedBackend, ResolvedCreds, SecretResolver, resolve_tool_creds};
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

/// Addresses the daemon actually bound. A configured port 0 resolves to
/// the OS-assigned port here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundAddrs {
    pub agent: SocketAddr,
    pub admin_https: Option<SocketAddr>,
    pub bootstrap: Option<SocketAddr>,
}

/// Run the daemon to completion. Returns when both listeners shut down
/// (or the drain window expires).
pub async fn run(config: AppConfig, coord: ShutdownCoordinator) -> Result<(), DaemonError> {
    run_reporting(config, coord, None).await
}

/// [`run`], additionally sending the bound addresses once every listener
/// is bound. A daemon that fails before that point drops `bound` unsent.
pub async fn run_reporting(
    config: AppConfig,
    coord: ShutdownCoordinator,
    bound: Option<oneshot::Sender<BoundAddrs>>,
) -> Result<(), DaemonError> {
    // Outbound TLS also needs a provider when every inbound listener is plain.
    crate::admin::https::install_crypto_provider_once();
    let _state_lock = state_lock::acquire(config.database.as_ref().map(|db| db.path.as_path()))?;
    oauth::owned(config, coord, bound).await
}

/// A listener's serve future, bound and fully prepared but not yet spawned.
type ListenerServe =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), std::io::Error>> + Send>>;
type ListenerTask = tokio::task::JoinHandle<Result<(), std::io::Error>>;

/// Bind the bootstrap-only listener (T6.8) and load its certificate, so
/// a taken port or a bad cert fails startup instead of the running
/// listener.
async fn bind_bootstrap(
    c: &crate::config::BootstrapOnlyConfig,
) -> Result<(std::net::TcpListener, axum_server::tls_rustls::RustlsConfig), DaemonError> {
    let failed = |e: std::io::Error| DaemonError::Server(format!("bootstrap-only listener: {e}"));
    let host: std::net::IpAddr = c.host.parse().map_err(|_| {
        DaemonError::AdminConfig(format!(
            "listen.bootstrap_only.host must be an IP address, got {:?}",
            c.host
        ))
    })?;
    let listener = crate::admin::https::bind(SocketAddr::new(host, c.port)).map_err(failed)?;
    let tls = crate::admin::https::load_tls_config(&c.cert_path, &c.key_path)
        .await
        .map_err(failed)?;
    Ok((listener, tls))
}

/// Reports a listener task's end on drop, so a panic is reported too.
struct ExitNotice {
    name: &'static str,
    exits: mpsc::UnboundedSender<&'static str>,
}

impl Drop for ExitNotice {
    fn drop(&mut self) {
        let _ = self.exits.send(self.name);
    }
}

/// Spawn a listener task that reports its end on `exits`, however it
/// ends. A listener that stops before shutdown has stopped serving; the
/// daemon watches `exits` so that failure is never deferred to shutdown
/// (AGENT-217).
fn spawn_listener(
    name: &'static str,
    exits: &mpsc::UnboundedSender<&'static str>,
    serve: ListenerServe,
) -> ListenerTask {
    let notice = ExitNotice {
        name,
        exits: exits.clone(),
    };
    tokio::spawn(async move {
        let _notice = notice;
        serve.await
    })
}

async fn run_owned(
    mut config: AppConfig,
    coord: ShutdownCoordinator,
    refresh_owner: crate::oauth::refresh::RefreshOwner,
    callbacks: crate::oauth::consent::server::Supervisor,
    bound: Option<oneshot::Sender<BoundAddrs>>,
) -> Result<(), DaemonError> {
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
    // T6.8: enrolment runs through the admin substrate's AdminService.
    if !admin_enabled
        && config
            .listen
            .bootstrap_only
            .as_ref()
            .is_some_and(|c| c.enabled)
    {
        return Err(DaemonError::AdminConfig(
            "listen.bootstrap_only is enabled but `listen.admin_socket` is not set".into(),
        ));
    }

    // M9 / v2.0.0: warn once when an operator carries `inbound_auth.token`
    // forward into a deployment with the admin substrate enabled. The
    // shared bearer is silently ignored on the agent listener; per-agent
    // bearer takes precedence.
    let inbound_auth_token_set = config
        .inbound_auth
        .as_ref()
        .and_then(|a| a.token.as_ref())
        .is_some();
    crate::deprecation::emit_inbound_auth_token_runtime_deprecation(
        &crate::deprecation::default_registry(),
        admin_enabled,
        inbound_auth_token_set,
    );

    let addr = SocketAddr::new(
        config.listen.host.parse().unwrap_or([127, 0, 0, 1].into()),
        config.listen.port,
    );
    // Bind the agent port before anything reads `listen.port`, and record
    // the port actually bound. A configured port 0 must not reach the MCP
    // self-loop guards (registration API, definitions, seed catalog) as 0,
    // which would let an upstream point back at this daemon (AGENT-217).
    let agent_listener = TcpListener::bind(addr)
        .await
        .map_err(|e| DaemonError::Server(format!("agent listener: {e}")))?;
    let agent_addr = agent_listener.local_addr()?;
    config.listen.port = agent_addr.port();

    // Wrap config in shared ArcSwap. Both the agent router (via
    // build_app_with_shared_config) and the AdminService observe this
    // same snapshot, so hot reload (T1.5) is unified across both
    // surfaces.
    let shared_config: Arc<ArcSwap<AppConfig>> = Arc::new(ArcSwap::from_pointee(config));

    // Admin substrate (DB + auth + service) — built before listener
    // binding so a misconfig fails fast. The same pool feeds the audit
    // repository handed to the agent router, so proxy writes share one
    // SQLite connection pool with admin reads.
    // Resolve tool credentials at startup (M5 / T5.1). The resolver
    // includes FileSealedBackend so tools using `from_file_sealed:`
    // get their credentials read from systemd-creds-decrypted files.
    // Vault and AWS variants surface NotImplemented per T5.3.
    for tool in &shared_config.load().tools {
        if tool.auth.as_ref().is_some_and(|auth| {
            matches!(auth.value, crate::secret::SecretRef::FromFileSealed { .. })
        }) {
            tracing::warn!(tool = %tool.name,
                "direct file-backed account bindings are unsupported; owner must import a sealed stored snapshot and explicitly select it for each registered agent");
        }
    }
    let resolver = SecretResolver::with_file_sealed(FileSealedBackend::new());
    let resolved_map = {
        let snapshot = shared_config.load();
        if admin_enabled {
            resolve_tool_creds(&snapshot, &resolver).await
        } else {
            if snapshot.tools.iter().any(|t| t.auth.is_some()) {
                tracing::warn!("{}", crate::legacy_admission::UPGRADE_MESSAGE);
            }
            Default::default()
        }
    };
    let resolved_creds: Arc<ArcSwap<ResolvedCreds>> = Arc::new(ArcSwap::from_pointee(resolved_map));
    let mut consent_callbacks = None;

    let (
        admin_state,
        audit_for_proxy,
        audit_for_sweeper,
        agent_auth,
        registrations_for_app,
        catalog_for_app,
        oauth_runtime_for_app,
        agent_creds_for_app,
        credential_sealing_key_for_app,
        credential_secrets_for_app,
        operational_log_for_app,
        operational_log_store_for_sweeper,
        op_resolver_for_app,
    ) = if admin_enabled {
        let setup =
            build_admin_substrate(shared_config.clone(), resolved_creds.clone(), refresh_owner)
                .await?;
        // The consent callback listener binds and serves with the other
        // listeners below, after every earlier bind succeeds (AGENT-217).
        consent_callbacks = setup
            .uds_state
            .oauth
            .as_ref()
            .and_then(|o| o.consent.clone());
        (
            Some(setup.uds_state),
            Some(setup.audit.clone()),
            Some(setup.audit),
            // M9: thread the agent authenticator into the agent listener
            // so `auth_middleware` enforces per-agent bearer authentication
            // on every request. The same Arc is also held by
            // `uds_state.agent_auth` so admin self-service operations and
            // the proxy hot path share one authenticator and one audit
            // fanout.
            Some(setup.agent_auth),
            // Phase E.3: thread the registrations repo into the agent
            // listener so `/tools` and `/models` discovery reads from
            // the registrations table. Same Arc as `uds_state.registrations`.
            Some(setup.registrations),
            // Phase E.6: same Arc as `uds_state.catalog`. Admin writes
            // refresh the catalog through that ref; the proxy hot path
            // reads through this one.
            Some(setup.catalog),
            // Phase F.5: OAuth runtime for the proxy hot path.
            setup.oauth_runtime,
            // Phase G: per-agent credential override repo.
            Some(setup.agent_creds),
            // Phase J: credential-store sealing key + sealed secrets repo.
            setup.credential_sealing_key,
            setup.credential_secrets,
            // Phase J / M2: operational-log emitter (proxy hot path) +
            // store (retention sweeper).
            Some(setup.operational_log),
            Some(setup.operational_log_store),
            // Phase J / M2: op:// resolver cache (proxy hot path, T2.3).
            Some(setup.op_resolver),
        )
    } else {
        (
            None, None, None, None, None, None, None, None, None, None, None, None, None,
        )
    };

    let refresh = oauth::Background::prepare(
        oauth_runtime_for_app.as_ref(),
        catalog_for_app.as_ref(),
        agent_creds_for_app.as_ref(),
        operational_log_for_app.as_ref(),
    );

    // Audit retention sweeper (T3.5). Runs only when admin substrate is
    // up — otherwise there's no audit to sweep. Defaults to
    // 90 days / hourly when `audit:` is absent from config.
    let mut sweeper_task = audit_for_sweeper.map(|audit| {
        let snapshot = shared_config.load();
        let cfg = snapshot.audit.as_ref().cloned().unwrap_or_default();
        drop(snapshot);
        let shutdown = coord.shutdown_signal();
        tokio::spawn(audit_retention_sweeper(audit, cfg, shutdown))
    });

    // Operational-log retention sweeper (T2.8). A SEPARATE interval task
    // from the audit sweeper, with its own retention window — sweeping the
    // operational-log stream never touches the audit table (LOG-1). Runs
    // only when the operational-log substrate is up; co-terminates with
    // shutdown like the audit sweeper.
    let mut ops_log_sweeper_task = operational_log_store_for_sweeper.map(|store| {
        let snapshot = shared_config.load();
        let cfg = snapshot
            .operational_log
            .as_ref()
            .cloned()
            .unwrap_or_default();
        drop(snapshot);
        let shutdown = coord.shutdown_signal();
        tokio::spawn(operational_log_retention_sweeper(store, cfg, shutdown))
    });

    // Credential-store sweeper (Phase J, ADR-0008). Collects sealed values
    // nothing references any more, then hard-deletes tombstoned rows past
    // retention. Runs only when the sealing key is configured (the store
    // exists only then).
    let mut credential_sweeper_task = credential_secrets_for_app.clone().map(|repo| {
        let snapshot = shared_config.load();
        let cfg = snapshot
            .credential_store
            .as_ref()
            .cloned()
            .unwrap_or_default();
        drop(snapshot);
        let shutdown = coord.shutdown_signal();
        tokio::spawn(credential_store_sweeper(repo, cfg, shutdown))
    });

    // Agent listener. Switch on auth_mode (post-v2 / #67):
    // - Bearer (default): plain TCP + axum (M0..M6 behavior).
    // - Mtls / Both: TLS-terminated TCP that verifies client certs at
    //   the handshake and stamps the peer cert into per-request
    //   extensions for the agent-auth middleware.
    let auth_mode = shared_config.load().listen.auth_mode;
    // T6.3/T6.4: CRL + emergency blocklist refresher for the agent listener.
    let mut revocation_task: Option<tokio::task::JoinHandle<()>> = None;
    let mtls_authenticator: Option<Arc<crate::mtls::MtlsAuthenticator>> = match auth_mode {
        crate::config::AuthMode::Bearer => None,
        _ => {
            let snap = shared_config.load();
            let mtls_cfg = snap.listen.mtls.as_ref().cloned().ok_or_else(|| {
                DaemonError::AdminConfig(
                    "auth_mode mtls/both requires `listen.mtls` config block".into(),
                )
            })?;
            drop(snap);
            let ca_pem = std::fs::read_to_string(&mtls_cfg.ca_bundle_path).map_err(|e| {
                DaemonError::AdminConfig(format!(
                    "read mtls.ca_bundle_path {}: {e}",
                    mtls_cfg.ca_bundle_path.display()
                ))
            })?;
            let validator = crate::mtls::MtlsValidator::new(&ca_pem)
                .map_err(|e| DaemonError::AdminConfig(format!("mtls validator: {e}")))?;
            let db_path = shared_config
                .load()
                .database
                .as_ref()
                .map(|d| d.path.clone())
                .ok_or_else(|| {
                    DaemonError::AdminConfig("auth_mode mtls/both requires `database.path`".into())
                })?;
            // The last good CRL lives beside the database (the state dir).
            let crl_cache = db_path.with_file_name("mtls-crl-cache.pem");
            let mut fetch_roots = vec![mtls_cfg.ca_bundle_path.clone()];
            if let Some(extra) = shared_config
                .load()
                .tls
                .as_ref()
                .and_then(|t| t.upstream_ca_bundle.clone())
            {
                fetch_roots.push(extra);
            }
            let revocation =
                crate::mtls::Revocation::load(&mtls_cfg, &ca_pem, &fetch_roots, &crl_cache)
                    .await
                    .map_err(DaemonError::AdminConfig)?;
            let validator = Arc::new(revocation.attach(validator));
            // Reuse the AgentRepository from the admin substrate when
            // available; fall back to a fresh open against the same DB.
            let pool = migrations::open_and_migrate(&db_path).await?;
            // Spawned after this block's fallible steps. Like the
            // sweepers, a later startup error leaves it running until
            // the runtime drops.
            if revocation.is_configured() {
                revocation_task = Some(tokio::spawn(revocation.run(coord.shutdown_signal())));
            }
            let agents = AgentRepository::new(pool);
            Some(Arc::new(crate::mtls::MtlsAuthenticator::with_audit(
                validator,
                agents,
                audit_for_proxy.clone(),
            )))
        }
    };

    // Phase E.6 — when the admin substrate is wired, the catalog was
    // built inside `build_admin_substrate` (after seed_loader + legacy
    // bootstrap). Same Arc threaded through both surfaces so admin
    // writes refresh in place and the proxy hot path observes the new
    // state without a daemon restart. Pre-Phase-E test paths that
    // skip the substrate get an empty catalog default from
    // `build_app_full_with_registrations`.
    // Phase J / M2 (LOG-1, config emit site): record that the daemon
    // loaded its configuration on the operational-log stream. Non-secret
    // context only (tool count + admin flag) — never a credential value.
    if let Some(emitter) = operational_log_for_app.as_ref() {
        let snap = shared_config.load();
        emitter.emit(
            crate::repo::LogLevel::Info,
            crate::repo::LogComponent::Config,
            "config_loaded",
            "daemon configuration loaded",
            Some(serde_json::json!({
                "tools": snap.tools.len(),
                "admin": admin_enabled,
            })),
        );
    }

    let observation = admin_state
        .as_ref()
        .and_then(|s| s.admin.native_authority());
    let native = crate::native::Runtime::with_authority(
        shared_config.load().mcp.clone(),
        registrations_for_app.clone(),
        catalog_for_app.clone().unwrap_or_default(),
        observation.clone(),
    );
    let mut native_task = native.start(coord.shutdown_signal());
    let agent_router = match catalog_for_app {
        Some(catalog) => crate::app::build_app_full_with_native(
            shared_config.clone(),
            audit_for_proxy,
            resolved_creds.clone(),
            mtls_authenticator,
            agent_auth,
            registrations_for_app,
            catalog,
            oauth_runtime_for_app,
            agent_creds_for_app,
            credential_sealing_key_for_app,
            credential_secrets_for_app,
            operational_log_for_app,
            op_resolver_for_app,
            native.clone(),
        ),
        None => crate::app::build_app_full_with_registrations(
            shared_config.clone(),
            audit_for_proxy,
            resolved_creds.clone(),
            mtls_authenticator,
            agent_auth,
            registrations_for_app,
        ),
    };
    let agent_shutdown = coord.shutdown_signal();
    // Every listener is bound and every fallible check done before any
    // serve task is spawned, so a startup failure leaves nothing serving.
    let agent_serve: ListenerServe = match auth_mode {
        crate::config::AuthMode::Bearer => {
            let listener = agent_listener;
            info!(addr = %agent_addr, mode = "bearer", "agent listener bound on {agent_addr} (bearer)");
            Box::pin(async move {
                axum::serve(listener, agent_router)
                    .with_graceful_shutdown(agent_shutdown)
                    .await
            })
        }
        _ => {
            let snap = shared_config.load();
            let mtls_cfg = snap.listen.mtls.as_ref().cloned().expect("checked above");
            drop(snap);
            let server_cert_path = mtls_cfg.server_cert_path.ok_or_else(|| {
                DaemonError::AdminConfig(
                    "auth_mode mtls/both requires `mtls.server_cert_path`".into(),
                )
            })?;
            let server_key_path = mtls_cfg.server_key_path.ok_or_else(|| {
                DaemonError::AdminConfig(
                    "auth_mode mtls/both requires `mtls.server_key_path`".into(),
                )
            })?;
            let ca_pem = std::fs::read_to_string(&mtls_cfg.ca_bundle_path)?;
            let listener = agent_listener;
            Box::pin(async move {
                crate::agent_listener::serve_mtls(
                    "agent listener",
                    listener,
                    &server_cert_path,
                    &server_key_path,
                    &ca_pem,
                    auth_mode,
                    agent_router,
                    agent_shutdown,
                )
                .await
            })
        }
    };

    // Admin UDS listener (when configured).
    // Admin HTTPS listener piggybacks on the same UdsState — same handlers,
    // different transport (T4.3 / C-3, SPEC §4.2.5).
    let mut admin_https_addr = None;
    let mut bootstrap_addr = None;
    let (admin_serve, admin_https_serve, bootstrap_serve): (
        Option<ListenerServe>,
        Option<ListenerServe>,
        Option<ListenerServe>,
    ) = if let Some(state) = admin_state {
        let path = admin_socket_path.expect("checked above");
        #[cfg(test)]
        let body_test_path = path.clone();
        let uds_shutdown = coord.shutdown_signal();
        let uds_state = state.clone();
        let uds_listener = crate::admin::uds::bind(&path)
            .map_err(|e| DaemonError::Server(format!("admin listener: {e}")))?;
        let uds: ListenerServe = Box::pin(async move {
            let result = crate::admin::uds::serve(uds_listener, uds_state, uds_shutdown).await;
            #[cfg(test)]
            crate::native_authority::body_probe::hold_listener(path, "uds").await;
            result
        });

        // Build the HTTPS task only when explicitly enabled. The block
        // present-but-disabled path is a no-op (off-by-default contract).
        let snapshot = shared_config.load();
        let https: Option<ListenerServe> = match snapshot
            .listen
            .admin_https
            .as_ref()
            .filter(|c| c.enabled)
        {
            None => None,
            Some(c) => {
                let host: std::net::IpAddr = c.host.parse().unwrap_or([127, 0, 0, 1].into());
                let addr = SocketAddr::new(host, c.port);
                let cert = c.cert_path.clone();
                let key = c.key_path.clone();
                let auth_mode = c.auth_mode;
                let https_shutdown = coord.shutdown_signal();
                let https_state_base = state.clone();
                let https_listener = crate::admin::https::bind(addr)
                    .map_err(|e| DaemonError::Server(format!("admin HTTPS listener: {e}")))?;
                admin_https_addr = Some(https_listener.local_addr()?);

                match auth_mode {
                    crate::config::AuthMode::Bearer => Some(Box::pin(async move {
                        let result = crate::admin::https::serve(
                            https_listener,
                            &cert,
                            &key,
                            https_state_base,
                            https_shutdown,
                        )
                        .await;
                        #[cfg(test)]
                        crate::native_authority::body_probe::hold_listener(body_test_path, "https")
                            .await;
                        result
                    })),
                    crate::config::AuthMode::Mtls | crate::config::AuthMode::Both => {
                        let mtls_cfg = c.mtls.as_ref().ok_or_else(|| {
                                    DaemonError::AdminConfig(format!(
                                        "admin_https.auth_mode={auth_mode:?} requires admin_https.mtls.ca_bundle_path"
                                    ))
                                })?;
                        let ca_pem = std::fs::read_to_string(&mtls_cfg.ca_bundle_path)?;
                        let validator = std::sync::Arc::new(
                            crate::mtls::MtlsValidator::new(&ca_pem).map_err(|e| {
                                DaemonError::AdminConfig(format!(
                                    "admin_https.mtls.ca_bundle_path: {e}"
                                ))
                            })?,
                        );
                        let mut https_state = https_state_base;
                        https_state.operator_mtls = Some(crate::admin::uds::OperatorMtlsContext {
                            auth_mode,
                            validator,
                        });
                        Some(Box::pin(async move {
                            let result = crate::admin::https::serve_mtls(
                                https_listener,
                                &cert,
                                &key,
                                &ca_pem,
                                auth_mode,
                                https_state,
                                https_shutdown,
                            )
                            .await;
                            #[cfg(test)]
                            crate::native_authority::body_probe::hold_listener(
                                body_test_path,
                                "https",
                            )
                            .await;
                            result
                        }))
                    }
                }
            }
        };
        let bootstrap_cfg = snapshot.listen.bootstrap_only.clone().filter(|c| c.enabled);
        drop(snapshot);
        let bootstrap = match bootstrap_cfg {
            None => None,
            Some(c) => {
                let (listener, tls) = bind_bootstrap(&c).await?;
                bootstrap_addr = Some(listener.local_addr()?);
                let state = crate::admin::bootstrap_listener::BootstrapState {
                    admin: state.admin.clone(),
                };
                let serve: ListenerServe = Box::pin(crate::admin::bootstrap_listener::serve(
                    listener,
                    tls,
                    state,
                    coord.shutdown_signal(),
                ));
                Some(serve)
            }
        };
        (Some(uds), https, bootstrap)
    } else {
        (None, None, None)
    };

    // All binds succeeded: record them and start serving.
    if let Some(rt) = &observation {
        rt.listeners.bound("agent", agent_addr);
    }
    let (exits, mut exited) = mpsc::unbounded_channel::<&'static str>();
    // The callback listener is the last bind: a failure here returns before
    // any listener task is spawned. Its exit is watched like the others.
    if let Some(consent) = consent_callbacks {
        let exits = exits.clone();
        callbacks
            .start(consent, move || {
                let _ = exits.send("OAuth consent callback listener");
            })
            .await
            .map_err(|e| DaemonError::AdminConfig(e.to_string()))?;
    }
    let mut agent_task = spawn_listener("agent listener", &exits, agent_serve);
    let mut admin_tasks: Vec<(&'static str, ListenerTask)> = [
        ("admin listener", admin_serve),
        ("admin HTTPS listener", admin_https_serve),
        ("bootstrap-only listener", bootstrap_serve),
    ]
    .into_iter()
    .filter_map(|(name, serve)| serve.map(|serve| (name, spawn_listener(name, &exits, serve))))
    .collect();

    drop(exits);
    if let Some(bound) = bound {
        let _ = bound.send(BoundAddrs {
            agent: agent_addr,
            admin_https: admin_https_addr,
            bootstrap: bootstrap_addr,
        });
    }

    let mut refresh_task = refresh.map(|task| task.spawn(&coord));
    // A listener that stops before shutdown has stopped serving: stop the
    // daemon now and report it rather than discovering it at shutdown.
    let early_exit = tokio::select! {
        biased;
        _ = coord.shutdown_signal() => None,
        Some(name) = exited.recv() => Some(name),
    };
    if let Some(name) = early_exit {
        error!(
            listener = name,
            "listener stopped before shutdown; shutting the daemon down"
        );
        coord.trigger();
    }
    let stopped_early = |name: &str| DaemonError::Server(format!("{name} stopped before shutdown"));
    let drain = async {
        if let Some(task) = refresh_task.as_mut() {
            let _ = task.await;
        }
        let _ = (&mut native_task).await;
        let listener_res = tokio::join!(
            &mut agent_task,
            futures_util::future::join_all(admin_tasks.iter_mut().map(|(_, task)| task)),
        );
        // Sweeper exits on its own when the shutdown signal fires; we
        // join it here so a slow tick can finish cleanly within the
        // drain window. Errors are logged but never poisoned shutdown.
        if let Some(s) = sweeper_task.as_mut() {
            let _ = s.await;
        }
        if let Some(s) = ops_log_sweeper_task.as_mut() {
            let _ = s.await;
        }
        if let Some(s) = credential_sweeper_task.as_mut() {
            let _ = s.await;
        }
        if let Some(s) = revocation_task.as_mut() {
            let _ = s.await;
        }
        listener_res
    };

    // Wait for the shutdown signal first, THEN apply the drain timeout.
    // The drain window is the post-signal grace period for in-flight
    // requests to complete, not a cap on the daemon's serving lifetime
    // (which was the pre-fix bug — see ShutdownCoordinator docs).
    match coord.await_shutdown_then_drain(drain).await {
        Ok((agent_res, admin_res)) => {
            let names = std::iter::once("agent listener").chain(admin_tasks.iter().map(|t| t.0));
            for (name, result) in names.zip(std::iter::once(agent_res).chain(admin_res)) {
                match result {
                    Ok(Err(e)) => return Err(DaemonError::Server(format!("{name}: {e}"))),
                    // A panicked listener is a failure, not a clean exit.
                    Err(e) => {
                        return Err(DaemonError::Server(format!("{name} task failed: {e}")));
                    }
                    Ok(Ok(())) => {}
                }
            }
            if let Some(name) = early_exit {
                return Err(stopped_early(name));
            }
            info!("clean shutdown complete");
            Ok(())
        }
        Err(_) => {
            warn!("drain window exceeded; closing listeners and finishing bounded owned cleanup");
            // The window is the in-flight requests' whole grace period
            // (config.example.yaml, m1 runbook): close the listeners now,
            // dropping requests still in flight, then give owned background
            // work its bounded cleanup.
            close_task(&mut agent_task).await;
            for (_, task) in admin_tasks.iter_mut() {
                close_task(task).await;
            }
            for task in [
                sweeper_task.as_mut(),
                ops_log_sweeper_task.as_mut(),
                credential_sweeper_task.as_mut(),
                revocation_task.as_mut(),
                refresh_task.as_mut(),
            ]
            .into_iter()
            .flatten()
            {
                finish_task(task).await;
            }
            finish_task(&mut native_task).await;
            let snapshot = native.snapshot();
            if snapshot.entries != 0 {
                return Err(DaemonError::Server(
                    "native session cleanup incomplete".into(),
                ));
            }
            if let Some(name) = early_exit {
                return Err(stopped_early(name));
            }
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

/// Periodically sweep operational-log rows older than `now -
/// retention_days` (T2.8, LOG-1/LOG-4). Independent of the audit sweeper:
/// its own interval, its own retention window, and a bounded `DELETE`
/// that only touches the `operational_logs` table. Exits cleanly when
/// the shutdown future resolves.
async fn operational_log_retention_sweeper(
    store: crate::repo::OperationalLogStore,
    cfg: crate::config::OperationalLogConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    const MS_PER_DAY: i64 = 24 * 60 * 60 * 1_000;
    let interval = Duration::from_secs(cfg.sweep_interval_seconds.max(1));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("operational-log sweeper: shutdown signal observed; exiting cleanly");
                return;
            }
            _ = ticker.tick() => {
                let cutoff = now_ms() - i64::from(cfg.retention_days) * MS_PER_DAY;
                match store.sweep(cutoff).await {
                    Ok(0) => {}
                    Ok(n) => info!(deleted = n, retention_days = cfg.retention_days, "operational-log retention sweep deleted rows"),
                    Err(e) => warn!(error = %e, "operational-log retention sweep failed; will retry next interval"),
                }
            }
        }
    }
}

/// Lower bound on `credential_store.orphan_grace_seconds`.
const MIN_ORPHAN_GRACE_SECONDS: u64 = 60;

/// Periodically garbage-collect the sealed credential store (Phase J,
/// ADR-0008). Each tick: tombstone live rows that no registration or
/// per-agent override references and that are older than the orphan grace
/// window, then hard-delete tombstoned rows older than the retention
/// window. `credential_secrets` timestamps are unix SECONDS. Exits cleanly
/// when the shutdown future resolves.
async fn credential_store_sweeper(
    repo: crate::repo::CredentialSecretsRepository,
    cfg: crate::config::CredentialStoreConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    const SECS_PER_DAY: i64 = 24 * 60 * 60;
    let interval = Duration::from_secs(cfg.sweep_interval_seconds.max(1));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("credential-store sweeper: shutdown signal observed; exiting cleanly");
                return;
            }
            _ = ticker.tick() => {
                let now = now_ms() / 1_000;
                // Floor the grace window: a near-zero value would let a sweep
                // tick land between sealing a value and recording its ref.
                let grace = i64::try_from(cfg.orphan_grace_seconds.max(MIN_ORPHAN_GRACE_SECONDS))
                    .unwrap_or(i64::MAX);
                match repo.tombstone_unreferenced(now.saturating_sub(grace)).await {
                    Ok(0) => {}
                    Ok(n) => info!(tombstoned = n, "credential-store sweep tombstoned unreferenced sealed values"),
                    Err(e) => warn!(error = %e, "credential-store orphan sweep failed; will retry next interval"),
                }
                let cutoff = now - i64::from(cfg.tombstone_retention_days) * SECS_PER_DAY;
                match repo.sweep(cutoff).await {
                    Ok(0) => {}
                    Ok(n) => info!(deleted = n, retention_days = cfg.tombstone_retention_days, "credential-store sweep deleted tombstoned rows"),
                    Err(e) => warn!(error = %e, "credential-store retention sweep failed; will retry next interval"),
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
/// the UDS router state, a clone of the AuditRepository so the proxy
/// hot path can write to the same audit table, and a clone of the
/// BearerAuthenticator (M9) — exposed as a trait object so the agent
/// listener can take it via `AppState.agent_auth` while `UdsState`
/// keeps the concrete type. Both consumers share one Arc and one
/// audit fanout.
struct AdminSetup {
    uds_state: UdsState,
    audit: AuditRepository,
    agent_auth: Arc<dyn crate::auth_v2::AgentAuthenticator>,
    /// Phase E.3 — registrations repo wired through both UdsState (for
    /// admin endpoints) and AppState (for /tools, /models discovery).
    /// Same Arc passed to both consumers.
    registrations: Arc<crate::registrations::RegistrationRepository>,
    /// Phase E.6 — in-memory catalog cache built from the registrations
    /// table after seed_loader + legacy_bootstrap. Same Arc shared
    /// across UdsState (for admin-write invalidation) and AppState (for
    /// proxy hot-path reads).
    catalog: Arc<ArcSwap<crate::registrations::Catalog>>,
    /// Phase F.5 — OAuth runtime for the proxy hot path.
    /// `None` when `LOCKSMITH_OAUTH_SEALING_KEY` is unset.
    oauth_runtime: Option<crate::app::OauthRuntime>,
    /// Phase G — per-agent credential overrides repo. Always populated
    /// when admin substrate is wired (the table is part of the base
    /// schema after migration 0005). Empty rows mean every lookup
    /// returns `None` and the registration default applies.
    agent_creds: crate::repo::AgentCredentialRepository,
    /// Phase J (ADR-0008) — credential-store sealing key. `None` when
    /// `LOCKSMITH_CREDENTIAL_SEALING_KEY` is unset (stored-credential
    /// routes not mounted; `stored_*` registrations fail loud at proxy
    /// time).
    credential_sealing_key: Option<crate::secret::CredentialSealingKey>,
    /// Phase J (ADR-0008) — sealed `credential_secrets` store. `Some`
    /// only when `credential_sealing_key` is present, so "no key" cleanly
    /// means "feature off".
    credential_secrets: Option<crate::repo::CredentialSecretsRepository>,
    /// Phase J / M2 (LOG-2) — operational-log emitter, shared across the
    /// proxy hot path (via `AppState`), the admin handlers (registry /
    /// agent emit sites), and the OAuth refresh task. Always present when
    /// the admin substrate is wired.
    operational_log: Arc<crate::operational_log_sink::OperationalLogEmitter>,
    /// Phase J / M2 — operational-log store, handed to the retention
    /// sweeper (T2.8). Same pool as the emitter's drain task.
    operational_log_store: crate::repo::OperationalLogStore,
    /// Phase J / M2 (CCS-8) — `op://` resolver cache, refreshed from the
    /// catalog at startup. Always present when the admin substrate is up;
    /// the cache is empty when no `op` registrations exist.
    op_resolver: Arc<crate::secret::OpResolver>,
}

async fn build_admin_substrate(
    config: Arc<ArcSwap<AppConfig>>,
    resolved_creds: Arc<ArcSwap<ResolvedCreds>>,
    refresh_owner: crate::oauth::refresh::RefreshOwner,
) -> Result<AdminSetup, DaemonError> {
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
    let registrations = Arc::new(crate::registrations::RegistrationRepository::new(
        pool.clone(),
    ));

    // Phase E.7 — apply the seed catalog before the daemon starts
    // serving traffic. Missing-file is non-fatal (deployments without
    // a baked-in catalog start with an empty registrations table);
    // parse / validation errors ABORT startup since a malformed
    // catalog ships with the image.
    let seed_listener = {
        let cfg = config.load();
        (cfg.listen.host.clone(), cfg.listen.port)
    };
    if let Some(seed_path) = crate::registrations::seed_loader::seed_path_from_env() {
        match crate::registrations::seed_loader::load_for_listener(
            &registrations,
            &seed_path,
            Some((&seed_listener.0, seed_listener.1)),
        )
        .await
        {
            Ok(()) => {}
            Err(e) => {
                return Err(DaemonError::AdminConfig(format!(
                    "seed catalog load failed (path={}): {e}",
                    seed_path.display()
                )));
            }
        }
    }

    // Phase E (transitional) — migrate pre-Phase-E `config.tools` YAML
    // entries into the registrations table. Runs AFTER the seed loader
    // so seed-catalog rows take precedence. Skips entries whose names
    // are already in the table; skips auth shapes we can't translate
    // (sealed-file / Vault / AWS) with a WARN log. Deprecated;
    // removed in v0.3.
    {
        let snapshot = config.load();
        if let Err(e) = crate::registrations::legacy_bootstrap::bootstrap_from_config_tools(
            &registrations,
            &snapshot,
        )
        .await
        {
            return Err(DaemonError::AdminConfig(format!(
                "legacy config.tools bootstrap: {e}"
            )));
        }
    }

    let mut audit = AuditRepository::new(pool.clone());

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

    // Phase J / M2 (LOG-2) — operational-log emitter + its drain task.
    // Built unconditionally when the admin substrate is up (the table is
    // part of the base schema after migration 0008). The emitter is
    // shared across the proxy hot path (via `AppState`), the admin
    // handlers (registry / agent emit sites), and the OAuth refresh task;
    // the store is handed to the retention sweeper (T2.8). Constructed
    // here — ahead of `AdminService` + the refresh task — so both can take
    // a clone.
    let operational_log_store = crate::repo::OperationalLogStore::new(pool.clone());
    let operational_log = Arc::new(crate::operational_log_sink::OperationalLogEmitter::spawn(
        operational_log_store.clone(),
        crate::operational_log_sink::DEFAULT_CAPACITY,
    ));

    // Construct once as a concrete Arc so `UdsState` (which holds the
    // concrete type) and the agent listener (which takes the trait
    // object via `AppState.agent_auth`) share the same authenticator
    // and the same audit fanout. The concrete Arc unsizes to
    // `Arc<dyn ...>` for the trait-object bind below.
    let bearer = Arc::new(
        BearerAuthenticator::with_audit(agents.clone(), Some(audit.clone()))
            .map_err(|e| DaemonError::AdminConfig(format!("agent auth: {e}")))?,
    );
    let operator_auth = OperatorAuthenticator::load_with_audit(&ops_path, Some(audit.clone()))
        .map_err(|e| DaemonError::OperatorCreds(e.to_string()))?;
    info!(operator_credentials = %ops_path.display(), "operator authenticator loaded");

    let admin = AdminService::with_audit_and_creds(
        agents,
        bootstrap,
        config.clone(),
        Some(audit.clone()),
        resolved_creds.clone(),
    )
    .with_operational_log(operational_log.clone());

    let agent_auth_dyn: Arc<dyn crate::auth_v2::AgentAuthenticator> = bearer.clone();

    // Phase E.6 — build the in-memory catalog from the registrations
    // table now that seed_loader + legacy_bootstrap have populated it.
    // Extend resolved_creds with env-var values referenced by AuthSpec
    // entries (seed catalog rows that aren't in config.tools).
    let cat = crate::registrations::Catalog::from_repo(registrations.as_ref())
        .await
        .map_err(|e| DaemonError::AdminConfig(format!("catalog load: {e}")))?;
    let extra = crate::secret::resolve_registration_creds_sync_env_only(&cat);
    if !extra.is_empty() {
        let snap = resolved_creds.load();
        let mut merged = (**snap).clone();
        for (k, v) in extra {
            merged.entry(k).or_insert(v);
        }
        resolved_creds.store(Arc::new(merged));
    }
    let catalog: Arc<ArcSwap<crate::registrations::Catalog>> = Arc::new(ArcSwap::from_pointee(cat));

    // Phase J (ADR-0008) — credential-store sealing key. Built only when
    // the operator supplies `LOCKSMITH_CREDENTIAL_SEALING_KEY` — distinct
    // from the OAuth key so the two sealing domains have independent
    // blast radius. When absent, the stored-credential admin routes 404
    // (feature off) and any `stored_*` registration fails loud with a
    // `503 credential_unresolved` at proxy time (T1.6). The sealed store
    // is constructed only when the key is present so "no key" cleanly
    // means "feature off".
    let (credential_sealing_key, credential_secrets) =
        match crate::secret::CredentialSealingKey::from_env() {
            Ok(key) => {
                info!("credential store: sealing key loaded; stored-credential routes mounted");
                let secrets = crate::repo::CredentialSecretsRepository::new(pool.clone());
                (Some(key), Some(secrets))
            }
            Err(crate::oauth::SealingKeyError::EnvVarUnset { .. }) => {
                info!(
                    "credential store: LOCKSMITH_CREDENTIAL_SEALING_KEY unset; stored-credential routes not mounted"
                );
                (None, None)
            }
            Err(e) => {
                return Err(DaemonError::AdminConfig(format!(
                    "credential sealing key: {e}"
                )));
            }
        };

    // Phase F.4 — OAuth admin state. Built only when the operator
    // supplies `LOCKSMITH_OAUTH_SEALING_KEY`. When absent, OAuth
    // registrations exist in the catalog but bootstrap calls fail
    // cleanly with a 404 (the routes aren't mounted) and OAuth proxy
    // calls return 503 (Phase F.5 surfaces that envelope code).
    let (oauth_admin, oauth_runtime) = match crate::oauth::SealingKey::from_env() {
        Ok(key) => {
            let sessions = crate::oauth::OauthSessionRepository::new(pool.clone());
            let locks = crate::oauth::refresh::RefreshLockMap::with_owner(refresh_owner.clone());
            info!("oauth: sealing key loaded; refresh task prepared");
            let refresh_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());
            let consent = match config.load().oauth_consent.clone() {
                Some(c) => Some(
                    crate::oauth::consent::Runtime::with_client_key(
                        pool.clone(),
                        key.clone(),
                        c,
                        refresh_owner.clone(),
                        credential_sealing_key.clone(),
                    )
                    .await
                    .map_err(|e| DaemonError::AdminConfig(e.to_string()))?,
                ),
                None => None,
            };
            let admin = crate::oauth::OauthAdminState {
                consent,
                registrations: registrations.clone(),
                sessions: sessions.clone(),
                sealing_key: key.clone(),
                catalog: catalog.clone(),
                locks: locks.clone(),
                device_logins: Default::default(),
            };
            let runtime = crate::app::OauthRuntime {
                sessions,
                sealing_key: key,
                locks,
                refresh_client,
            };
            (Some(admin), Some(runtime))
        }
        Err(crate::oauth::SealingKeyError::EnvVarUnset { .. }) => {
            if config.load().oauth_consent.is_some() {
                return Err(DaemonError::AdminConfig(
                    "oauth_consent requires OAuth sealing key".into(),
                ));
            }
            info!("oauth: LOCKSMITH_OAUTH_SEALING_KEY unset; OAuth admin routes not mounted");
            (None, None)
        }
        Err(e) => {
            return Err(DaemonError::AdminConfig(format!("oauth sealing key: {e}")));
        }
    };

    // Phase J / M2 (LOG-2) — operational-log emitter + its drain task.
    // Built unconditionally when the admin substrate is up (the table is
    // Phase J / M2 (CCS-8) — `op://` resolver. Built with the real `op`
    // CLI command, then synced from the catalog + per-agent overrides so
    // every `op` reference in use is resolved into the cache BEFORE traffic
    // starts. A missing `op` binary or a failed read degrades that one
    // reference (logged on the operational-log stream) — the daemon still
    // boots. Admin handlers resync on every catalog / override change
    // (T2.2). Never per request.
    let op_resolver = Arc::new(crate::secret::OpResolver::with_cli(Some(
        operational_log.clone(),
    )));
    let agent_creds_repo = crate::repo::AgentCredentialRepository::new(pool.clone());
    crate::secret::resync_op_references(&op_resolver, &catalog, Some(&agent_creds_repo)).await;
    if op_resolver.cached_count() > 0 {
        info!(
            count = op_resolver.cached_count(),
            "resolved op:// references at startup"
        );
    }

    let roots =
        crate::native_authority::runtime::roots(config.load().mcp.upstream_ca_bundle.as_deref())
            .map_err(|e| DaemonError::AdminConfig(e.to_string()))?;
    let authority = Arc::new(
        crate::native_authority::runtime::Runtime::new(
            registrations.clone(),
            catalog.clone(),
            credential_sealing_key.clone(),
            roots,
            refresh_owner,
        )
        .await
        .map_err(|e| DaemonError::AdminConfig(e.to_string()))?
        .with_consent(oauth_admin.as_ref().and_then(|a| a.consent.clone())),
    );
    authority.listeners.expect("agent");
    if config
        .load()
        .listen
        .admin_https
        .as_ref()
        .is_some_and(|c| c.enabled)
    {
        authority.listeners.expect("admin");
    }
    let admin = admin.with_native_authority(authority);

    Ok(AdminSetup {
        uds_state: UdsState {
            admin: Arc::new(admin),
            agent_auth: bearer,
            operator_auth: Arc::new(operator_auth),
            operator_mtls: None,
            registrations: Some(registrations.clone()),
            catalog: Some(catalog.clone()),
            resolved_creds: Some(resolved_creds.clone()),
            oauth: oauth_admin,
            agent_creds: Some(agent_creds_repo.clone()),
            credential_sealing_key: credential_sealing_key.clone(),
            credential_secrets: credential_secrets.clone(),
            operational_log: Some(operational_log.clone()),
            operational_log_store: Some(operational_log_store.clone()),
            op_resolver: Some(op_resolver.clone()),
        },
        audit,
        agent_auth: agent_auth_dyn,
        registrations,
        catalog,
        oauth_runtime,
        agent_creds: agent_creds_repo,
        credential_sealing_key,
        credential_secrets,
        operational_log,
        operational_log_store,
        op_resolver,
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

/// A daemon whose listeners are all bound, from [`start_with_drain_window`].
pub struct StartedDaemon {
    pub coord: ShutdownCoordinator,
    pub handle: tokio::task::JoinHandle<Result<(), DaemonError>>,
    pub addrs: BoundAddrs,
}

/// Spawn the runtime and wait until every listener is bound, returning the
/// actually bound addresses. Configure port 0 to let the OS choose: a port
/// probed and released by the caller can be taken before the daemon binds
/// it. A daemon that fails during startup returns its own error here.
pub async fn start_with_drain_window(
    config: AppConfig,
    drain: Duration,
) -> Result<StartedDaemon, DaemonError> {
    let coord = ShutdownCoordinator::new(drain);
    let (tx, rx) = oneshot::channel();
    let coord_clone = coord.clone();
    let mut handle =
        tokio::spawn(async move { run_reporting(config, coord_clone, Some(tx)).await });
    match rx.await {
        Ok(addrs) => Ok(StartedDaemon {
            coord,
            handle,
            addrs,
        }),
        Err(_) => match (&mut handle).await {
            Ok(Err(e)) => Err(e),
            Ok(Ok(())) => Err(DaemonError::Server(
                "daemon exited before binding its listeners".into(),
            )),
            Err(e) => Err(DaemonError::Server(format!("daemon task failed: {e}"))),
        },
    }
}

async fn close_task<T>(task: &mut tokio::task::JoinHandle<T>) {
    // A completed handle may already have been consumed by the drain future.
    if task.is_finished() {
        return;
    }
    task.abort();
    let _ = (&mut *task).await;
}

async fn finish_task<T>(task: &mut tokio::task::JoinHandle<T>) {
    // A completed handle may already have been consumed by the drain future.
    if task.is_finished() {
        return;
    }
    if tokio::time::timeout(Duration::from_secs(6), &mut *task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

#[cfg(test)]
#[path = "daemon/native_body/tests.rs"]
mod native_body_tests;

#[cfg(test)]
pub(crate) fn body_test_lock(path: &std::path::Path) -> std::io::Result<Option<std::fs::File>> {
    state_lock::acquire(Some(path))
}
