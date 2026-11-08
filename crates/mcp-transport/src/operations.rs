use crate::{
    Client,
    body::Body,
    error::{Result, fail},
};
use futures_util::stream::BoxStream;
use http::{HeaderName, HeaderValue, Method};
use rmcp::{
    model::ClientJsonRpcMessage,
    transport::streamable_http_client::{
        SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
    },
};
use sse_stream::Sse;
use std::{collections::HashMap, sync::Arc};

impl StreamableHttpClient for Client {
    type Error = crate::Error;
    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session: Option<Arc<str>>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse> {
        self.post_message_with_max_sse_event_size(
            uri,
            message,
            session,
            auth,
            headers,
            self.limits.event_bytes,
        )
        .await
    }
    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session: Option<Arc<str>>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
        max: usize,
    ) -> Result<StreamableHttpPostResponse> {
        check_version(&message)?;
        let attached = session.is_some();
        let response = self
            .request(Method::POST, uri, session, auth, headers)?
            .json(&message)
            .send()
            .await
            .map_err(|e| StreamableHttpError::Client(crate::request::io_error(e)))?;
        self.reply(response, &message, attached, max).await
    }
    async fn get_stream(
        &self,
        uri: Arc<str>,
        session: Option<Arc<str>>,
        last: Option<String>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, std::result::Result<Sse, SseError>>> {
        self.get_stream_with_max_sse_event_size(
            uri,
            session,
            last,
            auth,
            headers,
            self.limits.event_bytes,
        )
        .await
    }
    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session: Option<Arc<str>>,
        last: Option<String>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
        max: usize,
    ) -> Result<BoxStream<'static, std::result::Result<Sse, SseError>>> {
        if last.is_some() {
            return Err(fail("resume_unsupported"));
        }
        // rmcp's common SSE worker can retry before consulting its retry policy.
        self.begin_get().map_err(StreamableHttpError::Client)?;
        let response = self
            .request(Method::GET, uri, session, auth, headers)?
            .send()
            .await
            .map_err(|e| StreamableHttpError::Client(crate::request::io_error(e)))?;
        self.get_reply(response, max)
    }
    async fn delete_session(
        &self,
        uri: Arc<str>,
        session: Arc<str>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<()> {
        let response = self
            .request(Method::DELETE, uri, Some(session), auth, headers)?
            .send()
            .await
            .map_err(|e| StreamableHttpError::Client(crate::request::io_error(e)))?;
        crate::headers::body(&response, self.limits).map_err(StreamableHttpError::Client)?;
        self.challenge(&response)?;
        if response.status().is_success()
            || response.status() == http::StatusCode::METHOD_NOT_ALLOWED
        {
            Ok(())
        } else {
            Err(fail("http_status"))
        }
    }
}

impl Client {
    fn get_reply(
        &self,
        response: reqwest::Response,
        max: usize,
    ) -> Result<BoxStream<'static, std::result::Result<Sse, SseError>>> {
        crate::headers::body(&response, self.limits).map_err(StreamableHttpError::Client)?;
        self.challenge(&response)?;
        if response.status() == http::StatusCode::METHOD_NOT_ALLOWED {
            return Err(StreamableHttpError::ServerDoesNotSupportSse);
        }
        if !response.status().is_success() {
            return Err(fail("http_status"));
        }
        if !crate::headers::mime(&response)
            .map_err(StreamableHttpError::Client)?
            .eq_ignore_ascii_case("text/event-stream")
        {
            return Err(fail("content_type"));
        }
        self.event_stream(response, max)
    }
    fn event_stream(
        &self,
        response: reqwest::Response,
        max: usize,
    ) -> Result<BoxStream<'static, std::result::Result<Sse, SseError>>> {
        let mut limits = self.limits;
        limits.event_bytes = limits.event_bytes.min(max);
        if limits.event_bytes == 0 {
            return Err(fail("event_bytes"));
        }
        let body = Body::new(response, limits, self.metrics.clone())
            .map_err(StreamableHttpError::Client)?;
        Ok(crate::sse::stream(
            body,
            limits,
            self.metrics.clone(),
            self.validator,
        ))
    }
}

fn check_version(message: &ClientJsonRpcMessage) -> Result<()> {
    use rmcp::model::ClientRequest;
    if let ClientJsonRpcMessage::Request(request) = message
        && let ClientRequest::InitializeRequest(init) = &request.request
        && init.params.protocol_version.as_str() != "2025-11-25"
    {
        return Err(fail("protocol_version"));
    }
    Ok(())
}
