//! Agent listener bind variants (M6 follow-up / #67).
//!
//! The agent listener has two bind shapes selected by `listen.auth_mode`:
//!
//! - `Bearer` — plain TCP + axum (M0..M6 default; lives in
//!   `daemon::run` directly).
//! - `Mtls` / `Both` — TLS-terminated TCP that requires a client cert
//!   at the handshake. The peer cert DER is injected into per-request
//!   extensions so middleware can hand it to `MtlsAuthenticator`.
//!
//! This module lives outside `daemon` because it has its own per-
//! connection accept loop: axum-server's high-level `bind_rustls`
//! doesn't surface peer certificates to handlers cleanly. Doing the
//! accept loop manually with `tokio-rustls` keeps the peer-cert plumb-
//! ing local and explicit.

mod drain;

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{info, warn};

use crate::config::AuthMode;

/// Per-connection extension: the agent's client cert in DER form. Empty
/// when no client cert was presented (only possible under `auth_mode:
/// both`). The agent-auth middleware reads this from the request's
/// extensions, runs it through `MtlsValidator + MtlsAuthenticator`, and
/// resolves to an `AgentIdentity`.
#[derive(Clone, Debug)]
pub struct PeerCertDer(pub Option<Vec<u8>>);

/// Bind a TLS-terminated agent listener that requires (or optionally
/// accepts, under `Both`) client certs. Returns when the shutdown
/// future resolves.
pub async fn bind_and_serve_mtls(
    addr: SocketAddr,
    server_cert_path: &Path,
    server_key_path: &Path,
    ca_bundle_pem: &str,
    auth_mode: AuthMode,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), io::Error> {
    let listener = TcpListener::bind(addr).await?;
    serve_mtls(
        "agent listener",
        listener,
        server_cert_path,
        server_key_path,
        ca_bundle_pem,
        auth_mode,
        app,
        shutdown,
    )
    .await
}

/// Serve mTLS on `listener`. `name` labels its log lines, because the
/// admin HTTPS listener reuses this loop.
#[allow(clippy::too_many_arguments)]
pub async fn serve_mtls(
    name: &'static str,
    listener: TcpListener,
    server_cert_path: &Path,
    server_key_path: &Path,
    ca_bundle_pem: &str,
    auth_mode: AuthMode,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), io::Error> {
    let addr = listener.local_addr()?;
    crate::admin::https::install_crypto_provider_once();

    let server_config =
        build_server_config(server_cert_path, server_key_path, ca_bundle_pem, auth_mode)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    info!(addr = %addr, mode = ?auth_mode, "{name} (mTLS) bound");

    tokio::pin!(shutdown);
    let stop = tokio_util::sync::CancellationToken::new();
    let mut connections = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("{name} (mTLS): shutdown signal observed; closing accept loop");
                break;
            }
            _ = connections.join_next(), if !connections.is_empty() => {},
            accept = listener.accept() => {
                let (tcp, _peer) = match accept {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(error = %e, "{name}: accept failed");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let app = app.clone();
                connections.spawn(handle_conn(tcp, acceptor, app, stop.child_token()));
            }
        }
    }
    drain::close(&mut connections, &stop).await;
    Ok(())
}

async fn handle_conn(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    app: Router,
    stop: tokio_util::sync::CancellationToken,
) {
    let handshake = tokio::select! {
        biased;
        _ = stop.cancelled() => return,
        result = tokio::time::timeout(std::time::Duration::from_secs(5), acceptor.accept(tcp)) => result,
    };
    let Ok(handshake) = handshake else {
        return;
    };
    let tls = match handshake {
        Ok(t) => t,
        Err(e) => {
            // TLS handshake failures are expected (probes, wrong cert,
            // etc.) — log at debug and move on.
            tracing::debug!(error = %e, "tls handshake failed");
            return;
        }
    };

    // Capture peer cert before we hand the stream to hyper. Cloned
    // because the TlsStream borrow ends when we pass `io` along.
    let peer_cert_der: Option<Vec<u8>> = {
        let (_, conn) = tls.get_ref();
        conn.peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.as_ref().to_vec())
    };

    let io = TokioIo::new(tls);
    let peer_cert = PeerCertDer(peer_cert_der);

    // Per-request: clone the app + inject the peer cert extension,
    // then route. `oneshot` consumes the router clone for one request.
    let svc = service_fn(move |mut req: Request<hyper::body::Incoming>| {
        let app = app.clone();
        let peer_cert = peer_cert.clone();
        async move {
            req.extensions_mut().insert(peer_cert);
            let req = req.map(Body::new);
            Ok::<_, Infallible>(app.oneshot(req).await.into_response())
        }
    });

    let builder = ConnBuilder::new(hyper_util::rt::TokioExecutor::new());
    let connection = builder.serve_connection(io, svc);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => {
            if let Err(e) = result { tracing::debug!(error = %e, "tls connection serve error"); }
        },
        _ = stop.cancelled() => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut connection).await;
        }
    }
}

fn build_server_config(
    server_cert_path: &Path,
    server_key_path: &Path,
    ca_bundle_pem: &str,
    auth_mode: AuthMode,
) -> io::Result<ServerConfig> {
    // Server cert chain.
    let cert_pem = std::fs::read(server_cert_path)?;
    let key_pem = std::fs::read(server_key_path)?;
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("server cert parse: {e}"),
            )
        })?;
    if cert_chain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: no CERTIFICATE PEM blocks", server_cert_path.display()),
        ));
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("server key parse: {e}")))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: no PRIVATE KEY block", server_key_path.display()),
            )
        })?;

    // Client CA roots.
    let mut roots = rustls::RootCertStore::empty();
    let pem_blocks = pem::parse_many(ca_bundle_pem.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("ca bundle parse: {e}")))?;
    let mut added = 0;
    for block in pem_blocks {
        if block.tag() != "CERTIFICATE" {
            continue;
        }
        let der = CertificateDer::from(block.contents().to_vec());
        if roots.add(der).is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ca bundle: no usable trust anchors",
        ));
    }

    let verifier_builder = WebPkiClientVerifier::builder(Arc::new(roots));
    let verifier = match auth_mode {
        AuthMode::Mtls => verifier_builder.build(),
        AuthMode::Both => verifier_builder.allow_unauthenticated().build(),
        AuthMode::Bearer => unreachable!("bind_and_serve_mtls called with Bearer mode"),
    }
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("client cert verifier: {e}"),
        )
    })?;

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("server config: {e}")))?;
    Ok(server_config)
}

// Trait import shim for axum::Router::oneshot.
use axum::response::IntoResponse;
