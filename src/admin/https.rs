//! Admin HTTPS listener (T4.3, C-3 per SPEC §4.2.5).
//!
//! Same router shape as the UDS path (`crate::admin::uds::build_router`).
//! The only difference between the two transports is the bind layer:
//! TCP+TLS termination here, Unix-domain-socket+filesystem-permission
//! gate over there. Identical behavior is the M4 contract.
//!
//! Cert/key paths are listener-shape config (R-N5 carve-out): a change
//! requires a restart. PEM loading happens before `bind_rustls` so a
//! misconfiguration fails fast at startup.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Once;
use std::time::Duration;

use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use tracing::{info, warn};

use super::uds::UdsState;

/// rustls 0.23 requires a process-level CryptoProvider. Multiple
/// providers can end up linked (e.g. one through `reqwest` and another
/// through `axum-server`) so we install one explicitly. Idempotent
/// across calls; safe to invoke from both the daemon (server side) and
/// the CLI (client side, when talking to admin HTTPS).
pub fn install_crypto_provider_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // `install_default` returns Err if a provider is already
        // installed; that's fine and we treat it as a no-op.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Default drain window for in-flight HTTPS connections during graceful
/// shutdown. Matches the UDS path's `with_graceful_shutdown` behavior:
/// new connections rejected immediately, existing requests get a brief
/// window to complete before drop.
const HTTPS_GRACEFUL_DRAIN: Duration = Duration::from_secs(5);

/// Bind a TCP+TLS admin listener and serve the C-2 admin router. Returns
/// when the shutdown future resolves and active connections have drained
/// (or the per-connection drain window expires, whichever is first).
///
/// Failures from `RustlsConfig::from_pem_file` (missing file, malformed
/// PEM, unsupported key type) propagate as `std::io::Error` to the
/// caller, matching the UDS listener's error contract. The daemon
/// surfaces these as `DaemonError::Server` and exits.
/// Load and validate a TLS cert+key pair from PEM files. Public so the
/// daemon (and future hot-reload validators) can fail fast on bad
/// configuration before doing anything else.
///
/// Returns `InvalidData` when either path is missing, unreadable, or
/// not parseable as PEM. The error message names both paths to help
/// the operator pinpoint which file is at fault — matches T4.2's
/// fail-fast contract.
pub async fn load_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<RustlsConfig, std::io::Error> {
    install_crypto_provider_once();
    RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "TLS PEM load failed (cert={}, key={}): {e}",
                    cert_path.display(),
                    key_path.display()
                ),
            )
        })
}

pub async fn bind_and_serve(
    addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    state: UdsState,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let tls = load_tls_config(cert_path, key_path).await?;
    let app = super::uds::build_router(state);

    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        info!("admin HTTPS: shutdown signal observed; draining");
        shutdown_handle.graceful_shutdown(Some(HTTPS_GRACEFUL_DRAIN));
    });

    info!(addr = %addr, cert = %cert_path.display(), "admin HTTPS listener bound");
    let result = axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(app.into_make_service())
        .await;
    if let Err(e) = &result {
        warn!(error = %e, "admin HTTPS server exited with error");
    }
    result
}
