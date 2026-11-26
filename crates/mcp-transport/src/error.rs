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

/// Classify a refused exchange into a fixed name an operator can act on.
/// Names are static: no status text, header, body or credential survives.
pub fn failure_code(error: &StreamableHttpError<Error>) -> &'static str {
    if let Some(code) = io_code(error) {
        return code;
    }
    match error {
        StreamableHttpError::AuthRequired(_) => "unauthorized",
        StreamableHttpError::InsufficientScope(_) => "forbidden",
        StreamableHttpError::SessionExpired => "session_expired",
        StreamableHttpError::UnexpectedContentType(_) => "content_type",
        StreamableHttpError::UnexpectedServerResponse(_) if http_status(error).is_some() => {
            "status"
        }
        StreamableHttpError::Client(Error(code)) => match *code {
            "unauthorized" => "unauthorized",
            "forbidden" => "forbidden",
            "redirect" => "redirect",
            "http_status" => "status",
            "content_type" => "content_type",
            _ => "other",
        },
        _ => "other",
    }
}

/// Which refusal this was, by our own code or the SDK variant's fixed name.
/// Every value is a literal; nothing from the reply is carried.
pub fn failure_detail(error: &StreamableHttpError<Error>) -> &'static str {
    match error {
        StreamableHttpError::Client(Error(code)) => code,
        StreamableHttpError::Sse(_) => "sse",
        StreamableHttpError::Io(_) => "io",
        StreamableHttpError::UnexpectedEndOfStream => "unexpected_end_of_stream",
        StreamableHttpError::UnexpectedServerResponse(_) => "unexpected_server_response",
        StreamableHttpError::UnexpectedContentType(_) => "unexpected_content_type",
        StreamableHttpError::ServerDoesNotSupportSse => "server_does_not_support_sse",
        StreamableHttpError::Deserialize(_) => "deserialize",
        StreamableHttpError::TransportChannelClosed => "transport_channel_closed",
        StreamableHttpError::MissingSessionIdInResponse => "missing_session_id",
        StreamableHttpError::AuthRequired(_) => "auth_required",
        StreamableHttpError::InsufficientScope(_) => "insufficient_scope",
        StreamableHttpError::SessionExpired => "session_expired",
        _ => "other",
    }
}

/// The status of a non-2xx refusal that carried no JSON-RPC error.
pub fn http_status(error: &StreamableHttpError<Error>) -> Option<u16> {
    match error {
        StreamableHttpError::UnexpectedServerResponse(text) => {
            text.parse::<u16>().ok().filter(|n| (100..=599).contains(n))
        }
        _ => None,
    }
}

pub(crate) type Result<T> = std::result::Result<T, StreamableHttpError<Error>>;
pub(crate) fn fail(code: &'static str) -> StreamableHttpError<Error> {
    StreamableHttpError::Client(Error(code))
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
