use rmcp::transport::streamable_http_client::StreamableHttpError;

/// Static diagnostics deliberately exclude remote bytes and request secrets.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("mcp_transport_{0}")]
pub struct Error(pub &'static str);

/// Recover only classifications already made by this transport, without formatting errors.
pub fn io_code(mut error: &(dyn std::error::Error + 'static)) -> Option<&'static str> {
    for _ in 0..4 {
        let classified =
            error.downcast_ref::<Error>().copied().or_else(|| {
                match error.downcast_ref::<StreamableHttpError<Error>>() {
                    Some(StreamableHttpError::Client(e)) => Some(*e),
                    _ => None,
                }
            });
        if let Some(Error(code)) = classified {
            return match code {
                "deadline" => Some("deadline"),
                "http" => Some("http"),
                _ => None,
            };
        }
        error = error.source()?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_typed_closed_io_facts_survive_wrappers() {
        for code in ["deadline", "http"] {
            assert_eq!(io_code(&Error(code)), Some(code));
            assert_eq!(io_code(&fail(code)), Some(code));
            let event = sse_stream::Error::Body(Box::new(Error(code)));
            assert_eq!(io_code(&event), Some(code));
        }
        assert_eq!(io_code(&Error("invented-secret")), None);
        assert_eq!(io_code(&std::io::Error::other("deadline")), None);
    }
}

pub(crate) type Result<T> = std::result::Result<T, StreamableHttpError<Error>>;
pub(crate) fn fail(code: &'static str) -> StreamableHttpError<Error> {
    StreamableHttpError::Client(Error(code))
}
