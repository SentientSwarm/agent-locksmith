//! Thin wrapper over `agent_locksmith::admin::uds_client::UdsClient`
//! that owns token sourcing (env vars), JSON encoding, and the exit-code
//! mapping for HTTP statuses.

use std::path::Path;

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
    #[error("daemon returned {status}: {body}")]
    Server { status: u16, body: String },
    #[error("decode response: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl CliError {
    /// Map to the per-§4.7.2 exit codes.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::MissingOpToken | Self::MissingAgentToken | Self::MalformedAgentToken => 3,
            Self::Server { status: 401, .. } | Self::Server { status: 403, .. } => 3,
            Self::Server { status: 404, .. } => 4,
            Self::Server { status: 409, .. } => 5,
            _ => 1,
        }
    }
}

/// Variant token sources for a request.
pub enum Auth<'a> {
    Operator(&'a str),
    Agent(&'a str),
}

pub struct CliClient {
    inner: UdsClient,
}

impl CliClient {
    pub fn new(socket: &Path) -> Self {
        Self {
            inner: UdsClient::new(socket),
        }
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
        let auth_header_value: Option<String> = match auth {
            Auth::Operator(t) | Auth::Agent(t) => Some(format!("Bearer {t}")),
        };
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(v) = auth_header_value.as_deref() {
            headers.push(("authorization", v));
        }
        if body.is_some() {
            headers.push(("content-type", "application/json"));
        }
        let body_bytes = body.map(serde_json::to_vec).transpose()?;
        let (status, bytes) = self
            .inner
            .request(method, path, &headers, body_bytes)
            .await?;
        Ok((status, bytes))
    }
}
