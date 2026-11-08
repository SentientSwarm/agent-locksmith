use crate::{Error, Limits};
use reqwest::{Response, header::*};

pub(crate) fn body(response: &Response, limits: Limits) -> Result<(), Error> {
    framing(response.headers())?;
    for value in response.headers().get_all(CONTENT_ENCODING) {
        if !value.as_bytes().eq_ignore_ascii_case(b"identity") {
            return Err(Error("content_encoding"));
        }
    }
    if response
        .content_length()
        .is_some_and(|n| n > limits.response_bytes as u64)
    {
        return Err(Error("response_bytes"));
    }
    Ok(())
}
fn framing(headers: &HeaderMap) -> Result<(), Error> {
    let mut values = headers.get_all(TRANSFER_ENCODING).iter();
    if let Some(value) = values.next() {
        if headers.contains_key(CONTENT_LENGTH) {
            return Err(Error("framing"));
        }
        if !value.as_bytes().eq_ignore_ascii_case(b"chunked") || values.next().is_some() {
            return Err(Error("transfer_encoding"));
        }
    }
    Ok(())
}
pub(crate) fn mime(response: &Response) -> Result<&str, Error> {
    let value = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error("content_type"))?;
    let mut parts = value.split(';');
    let mime = parts.next().unwrap_or_default().trim();
    if parts.any(|p| {
        !p.trim().eq_ignore_ascii_case("charset=utf-8")
            && !p.trim().eq_ignore_ascii_case("charset=\"utf-8\"")
    }) {
        return Err(Error("content_type"));
    }
    Ok(mime)
}
pub(crate) fn session(response: &Response) -> Result<Option<String>, Error> {
    response
        .headers()
        .get("mcp-session-id")
        .map(|value| {
            let s = value.to_str().map_err(|_| Error("session_header"))?;
            if s.is_empty() || s.len() > 256 || !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                return Err(Error("session_header"));
            }
            Ok(s.to_owned())
        })
        .transpose()
}
