use crate::{
    Client,
    body::Body,
    error::{Result, fail},
};
use reqwest::{Response, StatusCode};
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_client::{StreamableHttpError, StreamableHttpPostResponse as Reply},
};

impl Client {
    pub(crate) async fn reply(
        &self,
        response: Response,
        message: &ClientJsonRpcMessage,
        attached: bool,
        event_limit: usize,
    ) -> Result<Reply> {
        if let Some(reply) = self.response_status(&response, attached)? {
            return Ok(reply);
        }
        let status = response.status();
        let session = crate::headers::session(&response).map_err(StreamableHttpError::Client)?;
        let mime = crate::headers::mime(&response).unwrap_or("").to_owned();
        let mut limits = self.limits;
        limits.event_bytes = limits.event_bytes.min(event_limit);
        if limits.event_bytes == 0 {
            return Err(fail("event_bytes"));
        }
        let body = Body::new(response, limits, self.metrics.clone())
            .map_err(StreamableHttpError::Client)?;
        if status.is_success() && mime.eq_ignore_ascii_case("text/event-stream") {
            return Ok(Reply::Sse(
                crate::sse::stream(body, limits, self.metrics.clone(), self.validator),
                session,
            ));
        }
        let bytes = body.collect().await.map_err(StreamableHttpError::Client)?;
        self.json_reply(status, &mime, &bytes, message, session)
    }
    fn response_status(&self, response: &Response, attached: bool) -> Result<Option<Reply>> {
        crate::headers::body(response, self.limits).map_err(StreamableHttpError::Client)?;
        self.challenge(response)?;
        let status = response.status();
        if status.is_redirection() {
            return Err(fail("redirect"));
        }
        if status == StatusCode::NOT_FOUND && attached {
            return Err(StreamableHttpError::SessionExpired);
        }
        if matches!(status, StatusCode::ACCEPTED | StatusCode::NO_CONTENT) {
            return Ok(Some(Reply::Accepted));
        }
        Ok(None)
    }
    fn json_reply(
        &self,
        status: StatusCode,
        mime: &str,
        bytes: &[u8],
        message: &ClientJsonRpcMessage,
        session: Option<String>,
    ) -> Result<Reply> {
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            return Err(fail("auth"));
        }
        if bytes.is_empty()
            && status.is_success()
            && !matches!(message, ClientJsonRpcMessage::Request(_))
        {
            return Ok(Reply::Accepted);
        }
        if !mime.eq_ignore_ascii_case("application/json") {
            return Err(fail("content_type"));
        }
        self.validate_raw(bytes)?;
        let decoded =
            crate::json::decode(bytes, self.limits).map_err(StreamableHttpError::Client)?;
        if status.is_success() || matches!(decoded, ServerJsonRpcMessage::Error(_)) {
            Ok(Reply::Json(decoded, session))
        } else {
            Err(fail("http_status"))
        }
    }
    fn validate_raw(&self, bytes: &[u8]) -> Result<()> {
        if let Some(validate) = self.validator {
            let raw = crate::strict_json::parse(bytes, self.limits)
                .map_err(StreamableHttpError::Client)?;
            validate(&raw).map_err(StreamableHttpError::Client)?;
        }
        Ok(())
    }
    pub(crate) fn challenge(&self, response: &Response) -> Result<()> {
        use rmcp::transport::streamable_http_client::{AuthRequiredError, InsufficientScopeError};
        let Some(value) = response.headers().get("www-authenticate") else {
            return Ok(());
        };
        let value = value.to_str().map_err(|_| fail("auth_header"))?;
        if value.len() > 4096 {
            return Err(fail("auth_header"));
        }
        match response.status() {
            StatusCode::UNAUTHORIZED => Err(StreamableHttpError::AuthRequired(
                AuthRequiredError::new(value.to_owned()),
            )),
            StatusCode::FORBIDDEN => Err(StreamableHttpError::InsufficientScope(
                InsufficientScopeError::new(value.to_owned(), scope(value)),
            )),
            _ => Ok(()),
        }
    }
}

fn scope(challenge: &str) -> Option<String> {
    let lower = challenge.to_ascii_lowercase();
    let start = lower.find("scope=")? + 6;
    let value = &challenge[start..];
    if let Some(quoted) = value.strip_prefix('"') {
        Some(quoted[..quoted.find('"')?].to_owned())
    } else {
        let value = value.split([',', ';', ' ']).next()?;
        (!value.is_empty()).then(|| value.to_owned())
    }
}
