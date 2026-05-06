//! Thin wrapper that routes admin requests over either the local UDS
//! (default) or the M4 admin HTTPS endpoint when `--admin-url` /
//! `LOCKSMITH_ADMIN_URL` is set. Owns token sourcing (env vars), JSON
//! encoding, and the exit-code mapping for HTTP statuses.

use std::path::Path;

use agent_locksmith::admin::https::install_crypto_provider_once;
use agent_locksmith::admin::uds_client::{UdsClient, UdsClientError};
use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("LOCKSMITH_OP_TOKEN env var not set")]
    MissingOpToken,
    #[error("LOCKSMITH_AGENT_TOKEN env var not set")]
    MissingAgentToken,
    #[error("LOCKSMITH_AGENT_TOKEN must be of form `lk_<id>.<secret>`")]
    MalformedAgentToken,
    #[error("transport: {0}")]
    Transport(#[from] UdsClientError),
    #[error("https transport: {0}")]
    HttpsTransport(String),
    #[error("invalid admin URL: {0}")]
    InvalidAdminUrl(String),
    #[error("daemon returned {status}: {body}")]
    Server { status: u16, body: String },
    #[error("decode response: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Usage-level error in argument parsing (e.g. malformed --auth spec).
    /// Exits 2 (per §4.7.2 usage convention).
    #[error("usage: {0}")]
    Usage(String),
}

impl CliError {
    /// Map to the per-§4.7.2 exit codes.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::MissingOpToken | Self::MissingAgentToken | Self::MalformedAgentToken => 3,
            Self::Server { status: 401, .. } | Self::Server { status: 403, .. } => 3,
            Self::Server { status: 404, .. } => 4,
            Self::Server { status: 409, .. } => 5,
            Self::InvalidAdminUrl(_) | Self::Usage(_) => 2,
            _ => 1,
        }
    }
}

/// Variant token sources for a request.
pub enum Auth<'a> {
    Operator(&'a str),
    Agent(&'a str),
}

/// Where the CLI sends its requests. Picked by the constructor based on
/// whether `--admin-url` / `LOCKSMITH_ADMIN_URL` was supplied.
enum Transport {
    Uds(UdsClient),
    Https {
        client: reqwest::Client,
        base_url: String,
    },
}

pub struct CliClient {
    transport: Transport,
}

impl CliClient {
    /// Construct a UDS-backed client at the given socket path. Kept for
    /// callers that don't need the admin-URL plumbing (and for ease of
    /// migration from the M2 single-transport client).
    pub fn new(socket: &Path) -> Self {
        Self {
            transport: Transport::Uds(UdsClient::new(socket)),
        }
    }

    /// Pick the right transport based on operator-supplied config.
    /// Precedence: `admin_url` (from --admin-url or LOCKSMITH_ADMIN_URL)
    /// → fall back to UDS at `socket`. When using HTTPS, an optional
    /// CA bundle path is loaded as an additional trusted root —
    /// required for self-signed / private-CA deployments (smallstep,
    /// openclaw-hardened, etc.).
    pub fn from_options(
        socket: &Path,
        admin_url: Option<&str>,
        ca_bundle: Option<&Path>,
    ) -> Result<Self, CliError> {
        if let Some(url) = admin_url {
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err(CliError::InvalidAdminUrl(format!(
                    "must start with https:// (got {url})"
                )));
            }
            install_crypto_provider_once();
            let mut builder = reqwest::Client::builder();
            if let Some(ca) = ca_bundle {
                let pem = std::fs::read(ca)?;
                let cert = reqwest::Certificate::from_pem(&pem)
                    .map_err(|e| CliError::HttpsTransport(format!("CA bundle: {e}")))?;
                builder = builder.add_root_certificate(cert);
            }
            let client = builder
                .build()
                .map_err(|e| CliError::HttpsTransport(format!("client build: {e}")))?;
            let base_url = url.trim_end_matches('/').to_string();
            return Ok(Self {
                transport: Transport::Https { client, base_url },
            });
        }
        Ok(Self::new(socket))
    }

    /// Read the operator token from `LOCKSMITH_OP_TOKEN`, returning a
    /// CliError if absent.
    pub fn op_token() -> Result<String, CliError> {
        std::env::var("LOCKSMITH_OP_TOKEN").map_err(|_| CliError::MissingOpToken)
    }

    /// Read the agent token from `LOCKSMITH_AGENT_TOKEN`.
    pub fn agent_token() -> Result<String, CliError> {
        std::env::var("LOCKSMITH_AGENT_TOKEN").map_err(|_| CliError::MissingAgentToken)
    }

    /// Send a JSON request and decode the response as type `T`. Maps
    /// non-2xx statuses to `CliError::Server` so commands can use `?`.
    pub async fn json<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        auth: Auth<'_>,
        body: Option<&Value>,
    ) -> Result<T, CliError> {
        let (status, bytes) = self.raw(method, path, auth, body).await?;
        if !(200..300).contains(&status) {
            return Err(CliError::Server {
                status,
                body: String::from_utf8_lossy(&bytes).to_string(),
            });
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Send a JSON request, ignoring the response body. Used for
    /// 204/no-content endpoints.
    pub async fn unit(
        &self,
        method: &str,
        path: &str,
        auth: Auth<'_>,
        body: Option<&Value>,
    ) -> Result<(), CliError> {
        let (status, bytes) = self.raw(method, path, auth, body).await?;
        if !(200..300).contains(&status) {
            return Err(CliError::Server {
                status,
                body: String::from_utf8_lossy(&bytes).to_string(),
            });
        }
        Ok(())
    }

    async fn raw(
        &self,
        method: &str,
        path: &str,
        auth: Auth<'_>,
        body: Option<&Value>,
    ) -> Result<(u16, bytes::Bytes), CliError> {
        let auth_header_value: String = match auth {
            Auth::Operator(t) | Auth::Agent(t) => format!("Bearer {t}"),
        };
        let body_bytes = body.map(serde_json::to_vec).transpose()?;
        match &self.transport {
            Transport::Uds(uds) => {
                let mut headers: Vec<(&str, &str)> =
                    vec![("authorization", auth_header_value.as_str())];
                if body.is_some() {
                    headers.push(("content-type", "application/json"));
                }
                let (status, bytes) = uds.request(method, path, &headers, body_bytes).await?;
                Ok((status, bytes))
            }
            Transport::Https { client, base_url } => {
                let url = format!("{base_url}{path}");
                let m = reqwest::Method::from_bytes(method.as_bytes())
                    .map_err(|e| CliError::HttpsTransport(format!("method: {e}")))?;
                let mut req = client
                    .request(m, &url)
                    .header("authorization", &auth_header_value);
                if let Some(b) = body_bytes {
                    req = req.header("content-type", "application/json").body(b);
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| CliError::HttpsTransport(e.to_string()))?;
                let status = resp.status().as_u16();
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| CliError::HttpsTransport(format!("read body: {e}")))?;
                Ok((status, bytes))
            }
        }
    }
}
