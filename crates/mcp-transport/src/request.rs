use crate::{
    Client, Error,
    error::{Result, fail},
};
use http::{HeaderName, HeaderValue, Method};
use std::{collections::HashMap, sync::Arc};

pub(crate) fn io_error(error: reqwest::Error) -> Error {
    if error.is_timeout() {
        Error("deadline")
    } else {
        Error("http")
    }
}
impl Client {
    pub(crate) fn request(
        &self,
        method: Method,
        uri: Arc<str>,
        session: Option<Arc<str>>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<reqwest::RequestBuilder> {
        let url = endpoint(&uri)?;
        let mut request = self
            .http
            .request(method, url)
            .header("accept", "application/json, text/event-stream")
            .header("accept-encoding", "identity");
        if let Some(token) = auth {
            request = request.bearer_auth(token);
        }
        if let Some(id) = session {
            request = request.header("mcp-session-id", id.as_ref());
        }
        custom(request, headers)
    }
}

fn endpoint(uri: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(uri).map_err(|_| fail("url"))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(fail("url"));
    }
    Ok(url)
}
fn custom(
    mut request: reqwest::RequestBuilder,
    headers: HashMap<HeaderName, HeaderValue>,
) -> Result<reqwest::RequestBuilder> {
    for (name, value) in headers {
        if matches!(
            name.as_str(),
            "accept"
                | "accept-encoding"
                | "authorization"
                | "host"
                | "content-length"
                | "transfer-encoding"
                | "content-encoding"
                | "content-type"
                | "mcp-session-id"
                | "last-event-id"
        ) {
            return Err(fail("reserved_header"));
        }
        if name == "mcp-protocol-version" && value != "2025-11-25" {
            return Err(fail("protocol_version"));
        }
        request = request.header(name, value);
    }
    Ok(request)
}
