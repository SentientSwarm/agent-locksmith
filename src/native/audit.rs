//! Best-effort lifecycle diagnostics, never a committed tool-admission record.
use super::context::Context;
use crate::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};
use std::time::Duration;

pub(super) async fn record(
    repo: &Option<AuditRepository>,
    context: &Context,
    operation: &'static str,
    allowed: bool,
) {
    let Some(repo) = repo else {
        return;
    };
    let (name, decision) = if allowed {
        ("native_lifecycle", Decision::Allowed)
    } else {
        ("native_tool_denied", Decision::Denied)
    };
    let event = AuditEvent {
        ts_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
        event_class: EventClass::Security,
        event: name.into(),
        agent_public_id: Some(context.identity.public_id.clone()),
        tool: Some(context.name.clone()),
        decision,
        details: Some(
            serde_json::json!({"operation":operation,"admission":"not_recorded_by_lifecycle"}),
        ),
        ..Default::default()
    };
    let _ = tokio::time::timeout(Duration::from_millis(50), repo.record(&event)).await;
}
