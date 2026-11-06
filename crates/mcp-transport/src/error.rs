use rmcp::transport::streamable_http_client::StreamableHttpError;

/// Static diagnostics deliberately exclude remote bytes and request secrets.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("mcp_transport_{0}")]
pub struct Error(pub &'static str);

pub(crate) type Result<T> = std::result::Result<T, StreamableHttpError<Error>>;
pub(crate) fn fail(code: &'static str) -> StreamableHttpError<Error> {
    StreamableHttpError::Client(Error(code))
}
