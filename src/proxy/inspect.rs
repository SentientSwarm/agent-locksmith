//! AGENT-262 — inspection hooks on the proxy path: the request body before
//! it is sent, and buffered responses before they reach the agent.

use super::{ProxyTarget, RequestCtx, audit_record};
use crate::app::AppState;
use crate::inspection::stream::StreamInspector;
use crate::inspection::{
    self, BodyMeta, Direction, DirectionPolicy, Outcome, Report, SkipReason, Verdict,
};
use crate::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::json;
use std::time::Duration;

/// The request policy for this route, if any.
pub(super) fn request_policy<'a>(state: &'a AppState, route: &str) -> Option<&'a DirectionPolicy> {
    state.inspection.policy(route)?.request.as_ref()
}

/// The response policy for this route, if any.
pub(super) fn response_policy<'a>(state: &'a AppState, route: &str) -> Option<&'a DirectionPolicy> {
    state.inspection.policy(route)?.response.as_ref()
}

/// Inspect the request body, with the decoded path and query as text
/// that is judged but never rewritten. `Ok` carries the body to send
/// (rewritten when redacted); `Err` is the 403 to return instead.
pub(super) async fn request(
    state: &AppState,
    ctx: &RequestCtx,
    headers: &HeaderMap,
    body: Bytes,
    extra: Vec<String>,
) -> Result<Bytes, Response> {
    let outcome = judge(
        state,
        &ctx.tool_name,
        Direction::Request,
        headers,
        body.clone(),
        extra,
    )
    .await;
    match outcome {
        Outcome::Forward {
            body: rewritten,
            report,
        } => {
            record(&state.audit, ctx, &report, None).await;
            Ok(rewritten.map(Bytes::from).unwrap_or(body))
        }
        Outcome::Block { report } => {
            record(&state.audit, ctx, &report, Some(403)).await;
            Err(blocked(
                StatusCode::FORBIDDEN,
                "request blocked by inspection",
            ))
        }
    }
}

/// How long one body may be scanned before `on_error` decides.
const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a blocking scan gave no answer.
#[derive(Debug, PartialEq, Eq)]
enum Unfinished {
    TimedOut,
    /// It panicked (a scanner bug).
    Failed,
}

/// Run `f` off the async workers. A timed-out scan keeps its blocking
/// thread until it ends; the deadline it carries (AGENT-276) stops its
/// out-of-process scanner calls, so that end comes soon after.
async fn run_blocking<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Unfinished> {
    let deadline = std::time::Instant::now() + timeout;
    let scan = move || crate::inspection::with_deadline(deadline, f);
    match tokio::time::timeout(timeout, tokio::task::spawn_blocking(scan)).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(Unfinished::Failed),
        Err(_) => Err(Unfinished::TimedOut),
    }
}

/// Inspect `body` under the route's policy for `direction`, on a
/// blocking thread with a deadline.
async fn judge(
    state: &AppState,
    route: &str,
    direction: Direction,
    headers: &HeaderMap,
    body: Bytes,
    extra: Vec<String>,
) -> Outcome {
    let inspection = state.inspection.clone();
    let owned_route = route.to_string();
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let encoded = encoded(headers);
    let scan = move || {
        let policy = direction_policy(&inspection, &owned_route, direction)
            .expect("judged routes have a policy");
        let meta = BodyMeta {
            content_type: content_type.as_deref(),
            encoded,
        };
        inspection::apply_with(policy, direction, meta, &body, &extra)
    };
    let why = match run_blocking(SCAN_TIMEOUT, scan).await {
        Ok(outcome) => return outcome,
        Err(Unfinished::TimedOut) => "timed out",
        Err(Unfinished::Failed) => "failed",
    };
    let closed = inspection::DirectionPolicy::closed();
    let policy = direction_policy(&state.inspection, route, direction).unwrap_or(&closed);
    inspection::unfinished(policy, direction, why)
}

fn direction_policy<'a>(
    inspection: &'a inspection::Inspection,
    route: &str,
    direction: Direction,
) -> Option<&'a DirectionPolicy> {
    let route = inspection.policy(route)?;
    match direction {
        Direction::Request => route.request.as_ref(),
        Direction::Response => route.response.as_ref(),
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

/// Is this response streamed (SSE or newline-delimited JSON)? Streamed
/// responses are not buffered for inspection.
pub(super) fn is_streamed(content_type: Option<&str>) -> bool {
    is_event_stream(content_type)
        || content_type.is_some_and(|c| {
            c.split(';').next().is_some_and(|t| {
                matches!(
                    t.trim().to_ascii_lowercase().as_str(),
                    "application/x-ndjson"
                        | "application/jsonl"
                        | "application/x-jsonlines"
                        | "application/stream+json"
                )
            })
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

/// Inspect a server-sent event stream as it passes (AGENT-265). `Err` is
/// the response to send instead: an encoded stream under `fail_closed`.
pub(super) async fn stream(
    policy: &DirectionPolicy,
    state: &AppState,
    ctx: &RequestCtx,
    headers: &HeaderMap,
    upstream: UpstreamStream,
) -> Result<UpstreamStream, Response> {
    if encoded(headers) {
        let report = Report {
            direction: Direction::Response,
            verdict: Verdict::Pass,
            hits: Vec::new(),
            dropped_hits: 0,
            skipped: Some(SkipReason::Encoded),
            error: None,
            redaction_incomplete: false,
        };
        let closed = policy.on_error == inspection::OnError::FailClosed;
        let report = if closed {
            Report {
                verdict: Verdict::Block,
                ..report
            }
        } else {
            report
        };
        record(&state.audit, ctx, &report, closed.then_some(502)).await;
        if closed {
            return Err(blocked(
                StatusCode::BAD_GATEWAY,
                "response blocked by inspection",
            ));
        }
        return Ok(upstream);
    }
    let inspector = StreamInspector::new(policy);
    if inspector.refused_up_front() {
        // AGENT-278: known before any byte is sent, so refuse with a 502
        // like an unscannable stream, rather than 200 headers and an
        // error event framed before the stream's protocol is known.
        let report = Report {
            verdict: Verdict::Block,
            ..inspector.report().clone()
        };
        record(&state.audit, ctx, &report, Some(502)).await;
        return Err(blocked(
            StatusCode::BAD_GATEWAY,
            "response blocked by inspection",
        ));
    }
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(drive(
        inspector,
        upstream,
        tx,
        state.audit.clone(),
        ctx.audit_event_base(),
    ));
    Ok(Box::pin(futures_util::stream::unfold(
        rx,
        |mut rx| async move { rx.recv().await.map(|item| (item, rx)) },
    )))
}

/// Pump the upstream through the inspector to the agent, then audit.
/// Returns the report it audited.
async fn drive(
    mut inspector: StreamInspector,
    mut upstream: UpstreamStream,
    tx: tokio::sync::mpsc::Sender<Result<Bytes, reqwest::Error>>,
    audit: Option<AuditRepository>,
    base: AuditEvent,
) -> Report {
    loop {
        // Held events may send nothing for a while, so a disconnect is
        // noticed here rather than only when a send fails.
        let next = tokio::select! {
            biased;
            _ = tx.closed() => break,
            next = upstream.next() => next,
        };
        let (step, failure) = match next {
            Some(Ok(chunk)) => (inspector.push(&chunk), None),
            // AGENT-273: a broken-off stream sends nothing more it holds.
            Some(Err(e)) => (inspector.abandon(), Some(e)),
            None => (inspector.finish(), None),
        };
        let mut gone = false;
        for out in step.out {
            if tx.send(Ok(Bytes::from(out))).await.is_err() {
                gone = true;
                break;
            }
        }
        if let Some(e) = failure {
            let _ = tx.send(Err(e)).await;
            break;
        }
        if gone || step.ended {
            break;
        }
    }
    // A disconnect leaves text unscanned: judge it for the audit (what
    // it would send has nowhere to go), but not the half event it cut.
    let _ = inspector.abandon();
    record_event(&audit, base.clone(), inspector.report(), None).await;
    if inspector.hold_overflowed() {
        let mut event = base;
        event.event_class = EventClass::Security;
        event.event = "inspection_hold_overflow".to_string();
        event.decision = Decision::Allowed;
        event.details = Some(json!({ "direction": "response" }));
        audit_record(&audit, event).await;
    }
    inspector.report().clone()
}

/// A streamed response on an inspected route is not scanned: audited,
/// and under `fail_closed` refused (`Some` is the 502 to send).
pub(super) async fn stream_unscanned(
    policy: &DirectionPolicy,
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
) -> Option<Response> {
    let closed = policy.on_error == inspection::OnError::FailClosed;
    let report = Report {
        direction: Direction::Response,
        verdict: if closed {
            Verdict::Block
        } else {
            Verdict::Pass
        },
        hits: Vec::new(),
        dropped_hits: 0,
        skipped: Some(SkipReason::Streaming),
        error: None,
        redaction_incomplete: false,
    };
    record(audit, ctx, &report, closed.then_some(502)).await;
    closed.then(|| blocked(StatusCode::BAD_GATEWAY, "response blocked by inspection"))
}

/// An upstream body as a stream of chunks.
pub(super) type UpstreamStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

/// What a buffered response inspection decided.
pub(super) enum Buffered {
    /// Send this body (inspected, possibly rewritten).
    Body(Vec<u8>),
    /// Too large to scan under `fail_open`: the prefix that was read
    /// followed by the rest of the upstream stream, unscanned.
    Unscanned(UpstreamStream),
    /// Send this response instead (a block).
    Respond(Response),
    /// Reading the upstream body failed; the caller audits it.
    ReadFailed(reqwest::Error),
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
    let meta = BodyMeta {
        content_type: None,
        encoded: encoded(&headers),
    };
    let mut stream = resp.bytes_stream();
    let mut prefix: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(c) => prefix.extend_from_slice(&c),
            Err(e) => return Buffered::ReadFailed(e),
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
                    Buffered::Unscanned(Box::pin(head.chain(stream)))
                }
            };
        }
    }
    let prefix = Bytes::from(prefix);
    let outcome = judge(
        state,
        &ctx.tool_name,
        Direction::Response,
        &headers,
        prefix.clone(),
        Vec::new(),
    )
    .await;
    match outcome {
        Outcome::Forward { body, report } => {
            record(audit, ctx, &report, None).await;
            Buffered::Body(body.unwrap_or_else(|| prefix.to_vec()))
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
    record_event(audit, ctx.audit_event_base(), report, status).await;
}

/// `record` with a request snapshot taken earlier (a stream's task).
async fn record_event(
    audit: &Option<AuditRepository>,
    mut event: AuditEvent,
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
        "count": hits.len() + report.dropped_hits,
        "hits": hits,
    });
    if report.dropped_hits > 0 {
        details["truncated"] = true.into();
    }
    if let Some(reason) = report.skipped {
        details["reason"] = reason.as_str().into();
    }
    if let Some(error) = &report.error {
        details["error"] = error.as_str().into();
    }
    if report.redaction_incomplete {
        details["redaction_incomplete"] = true.into();
    }
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
        super::encoded(&h)
    }

    #[tokio::test]
    async fn a_disconnected_agent_ends_a_held_stream() {
        let policy = DirectionPolicy {
            scanners: vec![std::sync::Arc::new(crate::inspection::dlp::Dlp)],
            on_hit: Verdict::Redact,
            on_error: inspection::OnError::FailOpen,
            max_scan_bytes: 1 << 20,
        };
        let first = futures_util::stream::once(async {
            Ok::<Bytes, reqwest::Error>(Bytes::from_static(b"data: {\"x\":\"held\"}\n\n"))
        });
        let upstream: UpstreamStream = Box::pin(first.chain(futures_util::stream::pending()));
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let task = tokio::spawn(drive(
            StreamInspector::new(&policy),
            upstream,
            tx,
            None,
            AuditEvent::default(),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(rx);
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("drive kept the upstream open after the agent left")
            .unwrap();
    }

    /// AGENT-273: an upstream that fails mid-stream gets its error passed
    /// on, and the text the inspector holds is dropped, not released.
    #[tokio::test]
    async fn an_upstream_error_drops_what_the_stream_holds() {
        let policy = DirectionPolicy {
            scanners: vec![std::sync::Arc::new(crate::inspection::dlp::Dlp)],
            on_hit: Verdict::Redact,
            on_error: inspection::OnError::FailOpen,
            max_scan_bytes: 1 << 20,
        };
        // An invalid URL: the request fails to build, giving a real error.
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let failure = client.get("http://").build().unwrap_err();
        let event = json!({"choices": [{"index": 0, "delta": {"content": "held text"}}]});
        let upstream: UpstreamStream = Box::pin(futures_util::stream::iter(vec![
            Ok(Bytes::from(format!("data: {event}\n\n"))),
            Err(failure),
        ]));
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(drive(
            StreamInspector::new(&policy),
            upstream,
            tx,
            None,
            AuditEvent::default(),
        ));
        let mut sent = Vec::new();
        while let Some(item) = rx.recv().await {
            sent.push(item);
        }
        assert!(
            matches!(sent.last(), Some(Err(_))),
            "the error is passed on"
        );
        let text: Vec<_> = sent.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert!(text.is_empty(), "held text was released: {text:?}");
    }

    #[tokio::test]
    async fn a_disconnect_still_audits_text_not_yet_scanned() {
        let policy = DirectionPolicy {
            scanners: vec![std::sync::Arc::new(crate::inspection::dlp::Dlp)],
            on_hit: Verdict::Flag,
            on_error: inspection::OnError::FailOpen,
            max_scan_bytes: 1 << 20,
        };
        // Assembled at run time: no credential-format literal in the repo.
        let key = format!(
            "ghp_{}",
            &"Qm7Zx2Lk9Vb4Nc8Rt1Hy6Jd3Fg5Sa0Wp".repeat(2)[..36]
        );
        let delta = |t: &str| {
            Ok::<Bytes, reqwest::Error>(Bytes::from(format!(
                "data: {}\n\n",
                json!({"choices": [{"index": 0, "delta": {"content": t}}]})
            )))
        };
        // The key arrives too small to trigger a scan.
        let first = futures_util::stream::iter(vec![delta(&"x ".repeat(500)), delta(&key)]);
        let upstream: UpstreamStream = Box::pin(first.chain(futures_util::stream::pending()));
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let task = tokio::spawn(drive(
            StreamInspector::new(&policy),
            upstream,
            tx,
            None,
            AuditEvent::default(),
        ));
        for _ in 0..2 {
            rx.recv().await.unwrap().unwrap();
        }
        drop(rx);
        let report = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("drive kept running after the agent left")
            .unwrap();
        assert_eq!(report.hits.len(), 1, "{report:?}");
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

    #[tokio::test]
    async fn a_slow_scan_gives_up_at_the_deadline() {
        let slow = run_blocking(Duration::from_millis(20), || {
            std::thread::sleep(Duration::from_millis(300));
            1
        });
        assert_eq!(slow.await, Err(Unfinished::TimedOut));
        assert_eq!(run_blocking(Duration::from_secs(5), || 2).await, Ok(2));
        let panicked = run_blocking(Duration::from_secs(5), || -> i32 { panic!("scanner bug") });
        assert_eq!(panicked.await, Err(Unfinished::Failed));
    }

    /// AGENT-276 — the scan's deadline is visible to the scanners it runs.
    #[tokio::test]
    async fn a_blocking_scan_carries_its_deadline() {
        let start = std::time::Instant::now();
        let deadline = run_blocking(Duration::from_secs(5), crate::inspection::scan_deadline)
            .await
            .unwrap()
            .expect("run_blocking sets a scan deadline");
        assert!(deadline > start && deadline <= start + Duration::from_secs(6));
        assert_eq!(crate::inspection::scan_deadline(), None);
    }

    #[test]
    fn ndjson_counts_as_streamed() {
        assert!(is_streamed(Some("application/x-ndjson")));
        assert!(is_streamed(Some("text/event-stream; charset=utf-8")));
        assert!(!is_streamed(Some("application/json")));
    }
}
