use super::{diagnostics::Trace, store};
use crate::repo::audit::{AuditEvent, Decision};
use serde_json::json;

pub(super) fn terminal(trace: &Trace, reason: &'static str, outcome: &'static str) -> AuditEvent {
    let mut event = trace
        .admission
        .clone()
        .unwrap_or_else(|| trace.base.clone());
    event.ts_ms = store::now() * 1000;
    event.event = match trace.phase {
        "not_admitted" => "native_tool_denied",
        "commit_submitted" => "native_tool_unknown",
        _ => "mcp_outcome",
    }
    .into();
    event.decision = match outcome {
        "success" => Decision::Allowed,
        "not_submitted" if trace.phase == "not_admitted" => Decision::Denied,
        _ => Decision::Error,
    };
    let details = event.details.get_or_insert_with(|| json!({}));
    details["operation_id"] = trace.id.clone().into();
    details["phase"] = trace.phase.into();
    details["reason"] = safe_reason(reason).into();
    details["outcome"] = outcome.into();
    details["retry"] = "never".into();
    event
}

pub(super) fn safe_reason(reason: &'static str) -> &'static str {
    if REASONS.contains(&reason) {
        reason
    } else {
        "request_refused"
    }
}

const REASONS: &[&str] = &[
    "compact_arguments",
    "compact_reference",
    "compact_cursor_changed",
    "compact_capacity",
    "compact_response_limit",
    "schema_required",
    "success",
    "tool_error",
    "tool_outcome_unknown",
    "request_cancelled",
    "operation_deadline",
    "shutting_down",
    "observation_capacity",
    "tools_list_required",
    "tool_not_approved",
    "argument_schema",
    "value_limit",
    "protected_argument",
    "review_invalid",
    "observation_required",
    "source_conflict",
    "source_unavailable",
    "authority_changed",
    "credential_unresolved",
    "native_account_unsupported",
    "upstream_secret_echo",
    "admission_audit_failed",
    "admission_commit_failed",
    "backend_unavailable",
    "upstream_http",
    "upstream_client",
    "upstream_protocol",
    "upstream_result",
    "destination_forbidden",
    "destination_invalid",
    "self_destination",
    "dns_empty",
    "dns_failed",
    "dns_limit",
    "listeners_pending",
    "explicit_selection_required",
    "agent_not_found",
    "upstream_observation_failed",
    "upstream_notification",
    "upstream_id",
    "upstream_session",
];

/// Project a borrowed RPC code into the same fixed diagnostic vocabulary.
pub(crate) fn safe_code(reason: &str) -> &'static str {
    REASONS
        .iter()
        .copied()
        .find(|r| *r == reason)
        .unwrap_or("request_refused")
}
