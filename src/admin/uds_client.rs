//! Minimal HTTP/1.1-over-Unix-domain-socket client.
//!
//! Used by the `locksmith` CLI to talk to the running daemon over its
//! admin UDS. Built directly on `hyper` 1.x's low-level connection API
//! rather than `hyper-util::Client` because the high-level client wants
//! a `Connector` impl that's overkill for a one-shot UDS request — we
//! never reuse connections and don't need pooling.
//!
//! Each `request` call:
//!   1. opens a fresh `tokio::net::UnixStream`
//!   2. completes a hyper http1 handshake on it
//!   3. sends the request, awaits the response, collects the body
//!   4. drops the connection
//!
//! No keepalive, no pool. UC-driven CLI calls are independent and the
//! daemon is local — connection cost is irrelevant.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

#[derive(Debug, thiserror::Error)]
pub enum UdsClientError {
    #[error("connect {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("handshake: {0}")]
    Handshake(hyper::Error),
    #[error("request: {0}")]
    Request(hyper::Error),
    #[error("body: {0}")]
    Body(hyper::Error),
    #[error("invalid header value: {0}")]
    Header(String),
    #[error("invalid method/uri: {0}")]
    BuildRequest(String),
}

#[derive(Clone)]
pub struct UdsClient {
    socket: PathBuf,
}

impl UdsClient {
    pub fn new(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: socket.as_ref().to_path_buf(),
        }
    }

    /// Send a single HTTP/1.1 request over a fresh UDS connection. The
    /// `headers` slice is `&[(name, value)]`; `body` is the raw request
    /// body (typically a serialized JSON document) or `None` for GET /
    /// DELETE requests.
    ///
    /// Returns `(status_u16, body_bytes)`. The caller is responsible for
    /// JSON-deserializing the body if applicable.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Bytes), UdsClientError> {
        let stream =
            UnixStream::connect(&self.socket)
                .await
                .map_err(|e| UdsClientError::Connect {
                    path: self.socket.clone(),
                    source: e,
                })?;
        let io = TokioIo::new(stream);

        let (mut sender, conn) = http1::handshake(io)
            .await
            .map_err(UdsClientError::Handshake)?;
        // Drive the connection in the background; drop when this scope
        // ends. http1 handshake yields a `Connection` future which must
        // be polled for the request to make progress.
        let conn_handle = tokio::spawn(async move {
            // The connection error is non-fatal at this level — the
            // request will surface its own error if the conn drops.
            let _ = conn.await;
        });

        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            // hyper http1 requires a Host header even over UDS. Use the
            // socket path as a stable, parseable token.
            .header("host", "locksmith.local");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }

        let body_full = match body {
            Some(b) => Full::new(Bytes::from(b)),
            None => Full::new(Bytes::new()),
        };
        let req = builder
            .body(body_full)
            .map_err(|e| UdsClientError::BuildRequest(e.to_string()))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(UdsClientError::Request)?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(UdsClientError::Body)?
            .to_bytes();

        // Allow the connection task to finish; it'll exit on its own
        // once both halves are dropped.
        conn_handle.abort();

        Ok((status, body))
    }
}
