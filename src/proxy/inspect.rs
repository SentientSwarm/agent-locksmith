//! AGENT-262 — inspection hooks on the proxy path: the request body before
//! it is sent, and buffered responses before they reach the agent.

use super::{ProxyTarget, RequestCtx, audit_record};
use crate::app::AppState;
use crate::inspection::{
    self, BodyMeta, Direction, DirectionPolicy, Outcome, Report, SkipReason, Verdict,
};
use crate::repo::audit::{AuditRepository, Decision, EventClass};
use axum::{
    Json,
    body::Body,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::json;

/// The request policy for this route, if any.
pub(super) fn request_policy<'a>(state: &'a AppState, route: &str) -> Option<&'a DirectionPolicy> {
    state.inspection.policy(route)?.request.as_ref()
}

/// The response policy for this route, if any.
pub(super) fn response_policy<'a>(state: &'a AppState, route: &str) -> Option<&'a DirectionPolicy> {
    state.inspection.policy(route)?.response.as_ref()
}

/// Inspect the request body. `Ok` carries the body to send (rewritten
/// when redacted); `Err` is the 403 to return instead.
pub(super) async fn request(
    policy: &DirectionPolicy,
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Bytes, Response> {
    match inspection::apply(policy, Direction::Request, meta(headers), &body) {
        Outcome::Forward {
            body: rewritten,
            report,
        } => {
            record(audit, ctx, &report, None).await;
            Ok(rewritten.map(Bytes::from).unwrap_or(body))
        }
        Outcome::Block { report } => {
            record(audit, ctx, &report, Some(403)).await;
            Err(blocked(
                StatusCode::FORBIDDEN,
                "request blocked by inspection",
            ))
        }
    }
}

fn meta(headers: &HeaderMap) -> BodyMeta<'_> {
    BodyMeta {
        content_type: headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        encoded: encoded(headers),
    }
}

/// True when any `Content-Encoding` value, or any comma-separated token
/// in one, is not `identity`. An unreadable value counts as encoded, so a
/// malformed header can't slip a compressed body past the scanners.
fn encoded(headers: &HeaderMap) -> bool {
    headers
        .get_all(axum::http::header::CONTENT_ENCODING)
        .iter()
        .any(|v| match v.to_str() {
            Ok(s) => s
                .split(',')
                .map(str::trim)
                .any(|t| !t.is_empty() && !t.eq_ignore_ascii_case("identity")),
            Err(_) => true,
        })
}

/// Is this response a server-sent event stream?
pub(super) fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|c| {
        c.split(';')
            .next()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"))
    })
}

/// Audit that a streamed response on an inspected route was not scanned.
pub(super) async fn record_stream_skipped(audit: &Option<AuditRepository>, ctx: &RequestCtx) {
    let report = Report {
        direction: Direction::Response,
        verdict: Verdict::Pass,
        hits: Vec::new(),
        skipped: Some(SkipReason::Streaming),
        error: None,
    };
    record(audit, ctx, &report, None).await;
}

/// What a buffered response inspection decided.
pub(super) enum Buffered {
    /// Send this body (inspected, possibly rewritten).
    Body(Vec<u8>),
    /// Too large to scan under `fail_open`: send the prefix that was read
    /// followed by the rest of the stream, unscanned.
    Unscanned(Body),
    /// Send this response instead (a block, or a body read failure).
    Respond(Response),
}

/// Read and inspect a non-streamed response.
pub(super) async fn response(
    policy: &DirectionPolicy,
    state: &AppState,
    ctx: &RequestCtx,
    _target: &ProxyTarget,
    resp: reqwest::Response,
) -> Buffered {
    let audit = &state.audit;
    let headers = resp.headers().clone();
    let meta = meta(&headers);
    let mut stream = resp.bytes_stream();
    let mut prefix: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(c) => prefix.extend_from_slice(&c),
            Err(_) => return Buffered::Respond(upstream_read_failed()),
        }
        if prefix.len() > policy.max_scan_bytes {
            let outcome = inspection::apply(policy, Direction::Response, meta, &prefix);
            return match outcome {
                Outcome::Block { report } => {
                    record(audit, ctx, &report, Some(502)).await;
                    Buffered::Respond(blocked(
                        StatusCode::BAD_GATEWAY,
                        "response blocked by inspection",
                    ))
                }
                Outcome::Forward { report, .. } => {
                    record(audit, ctx, &report, None).await;
                    let head = futures_util::stream::once(async move {
                        Ok::<Bytes, reqwest::Error>(Bytes::from(prefix))
                    });
                    Buffered::Unscanned(Body::from_stream(head.chain(stream)))
                }
            };
        }
    }
    match inspection::apply(policy, Direction::Response, meta, &prefix) {
        Outcome::Forward { body, report } => {
            record(audit, ctx, &report, None).await;
            Buffered::Body(body.unwrap_or(prefix))
        }
        Outcome::Block { report } => {
            record(audit, ctx, &report, Some(502)).await;
            Buffered::Respond(blocked(
                StatusCode::BAD_GATEWAY,
                "response blocked by inspection",
            ))
        }
    }
}

pub(super) fn upstream_read_failed() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": {"message": "upstream body read failed", "type": "upstream_error", "code": "upstream_error"}})),
    )
        .into_response()
}

fn blocked(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "type": "inspection_error", "code": "inspection_blocked", "message": message } })),
    )
        .into_response()
}

/// One security audit row per inspection that found, skipped or failed.
pub(super) async fn record(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    report: &Report,
    status: Option<u16>,
) {
    if report.is_quiet() {
        return;
    }
    let event_name = if !report.hits.is_empty() {
        "inspection_hit"
    } else if report.skipped.is_some() {
        "inspection_skipped"
    } else {
        "inspection_error"
    };
    let hits: Vec<_> = report
        .hits
        .iter()
        .map(|h| json!({ "scanner": h.scanner, "rule": h.rule, "sha256": h.sha256 }))
        .collect();
    let mut details = json!({
        "direction": report.direction.as_str(),
        "verdict": report.verdict.as_str(),
        "count": hits.len(),
        "hits": hits,
    });
    if let Some(reason) = report.skipped {
        details["reason"] = reason.as_str().into();
    }
    if let Some(error) = &report.error {
        details["error"] = error.as_str().into();
    }
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Security;
    event.event = event_name.to_string();
    event.status = status;
    event.decision = if report.verdict == Verdict::Block {
        Decision::Denied
    } else {
        Decision::Allowed
    };
    event.details = Some(details);
    audit_record(audit, event).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header::CONTENT_ENCODING};

    fn encoded(values: &[&[u8]]) -> bool {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(CONTENT_ENCODING, HeaderValue::from_bytes(v).unwrap());
        }
        meta(&h).encoded
    }

    #[test]
    fn any_non_identity_encoding_counts() {
        assert!(!encoded(&[]));
        assert!(!encoded(&[b"identity"]));
        assert!(encoded(&[b"gzip"]));
        assert!(encoded(&[b"identity", b"gzip"]), "a second header value");
        assert!(encoded(&[b"identity, br"]), "a comma-separated token");
        assert!(encoded(&[b"\xffgzip"]), "an unreadable value fails closed");
    }
}
