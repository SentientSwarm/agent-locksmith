//! AGENT-259 — a route whose client cannot be built answers 503 and is
//! audited; it is never retried without the proxy.

use super::{RequestCtx, audit_record};
use crate::client_pool::ClientUnavailable;
use crate::repo::audit::{AuditRepository, Decision, EventClass};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

pub(super) async fn record_egress_unavailable(
    audit: &Option<AuditRepository>,
    ctx: &RequestCtx,
    cause: ClientUnavailable,
) -> Response {
    let (event_name, code, message) = match cause {
        ClientUnavailable::ProxyUnconfigured => (
            "egress_unenforced",
            "egress_proxy_unconfigured",
            "route requires an egress proxy and none is configured",
        ),
        ClientUnavailable::BuildFailed => (
            "upstream_client_unavailable",
            "upstream_client_unavailable",
            "upstream client could not be built",
        ),
    };
    let mut event = ctx.audit_event_base();
    event.event_class = EventClass::Security;
    event.event = event_name.to_string();
    event.status = Some(503);
    event.decision = Decision::Error;
    audit_record(audit, event).await;
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": { "type": "egress_error", "code": code, "message": message } })),
    )
        .into_response()
}
