//! Operation-owned safe evidence; neither a durable outbox nor rollback proof.
use super::{Error, Result, control::Control, diagnostic_event, dispatch::Invocation, store};
use crate::{
    audit_sink::MirrorStatus,
    repo::audit::{AuditEvent, AuditRepository, EventClass},
};
use serde_json::{Value, json};

pub struct Trace {
    pub(super) id: String,
    pub(super) phase: &'static str,
    pub(super) base: AuditEvent,
    pub(super) admission: Option<AuditEvent>,
    pub(super) checked: Option<Value>,
    done: bool,
}

impl Trace {
    pub fn new(agent: &str, connection: &str) -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| Error("backend_unavailable"))?;
        let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            id,
            phase: "not_admitted",
            admission: None,
            checked: None,
            done: false,
            base: AuditEvent {
                ts_ms: store::now() * 1000,
                event_class: EventClass::Security,
                agent_public_id: Some(agent.into()),
                tool: Some(connection.into()),
                details: Some(json!({})),
                ..Default::default()
            },
        })
    }

    pub(super) fn approved(&mut self, call: &Invocation) {
        self.base.details = Some(json!({"operation_id":self.id,"tool_name":call.name,
            "contract_digest":call.digest,"source":call.source}));
    }

    pub(super) fn commit_submitted(&mut self, event: &AuditEvent) {
        self.phase = "commit_submitted";
        // A submitted event is not a confirmed admission; keep safe attribution only.
        self.base.details = event.details.clone();
    }

    pub(super) fn admitted(&mut self, event: AuditEvent) {
        self.phase = "admitted";
        self.admission = Some(event);
    }

    pub(super) fn submitted(&mut self) {
        self.phase = "submitted";
    }

    pub(super) fn checked(&mut self, value: &Value) {
        self.phase = "completed";
        self.checked = Some(value.clone());
    }

    pub async fn finish(
        &mut self,
        audit: &AuditRepository,
        control: &Control,
        result: &Result<Value>,
    ) {
        let (reason, outcome) = self.status(result);
        let event = diagnostic_event::terminal(self, reason, outcome);
        let deadline = diagnostic_deadline(control);
        let written = tokio::time::timeout_at(deadline, async {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            let status = audit.record_status(&event).await;
            let mirrored = if let Some(admission) = &self.admission {
                audit.mirror_status(admission).await
            } else {
                MirrorStatus::Absent
            };
            matches!(status, Ok(MirrorStatus::Written | MirrorStatus::Absent))
                && mirrored != MirrorStatus::Unavailable
        })
        .await
        .unwrap_or(false);
        if !written {
            unavailable(&self.id, self.phase);
        }
        self.done = true;
    }

    pub(super) fn interrupted(&mut self, result: &Result<Value>) {
        if self.done {
            return;
        }
        let reason = diagnostic_event::safe_reason(
            result
                .as_ref()
                .err()
                .map(|e| e.0)
                .unwrap_or("tool_outcome_unknown"),
        );
        tracing::warn!(
            operation_id = self.id,
            phase = self.phase,
            reason,
            "native_operation_interrupted"
        );
        self.done = true;
    }

    fn status(&self, result: &Result<Value>) -> (&'static str, &'static str) {
        match result {
            Ok(v) if self.phase == "completed" => {
                if v["isError"] == true {
                    ("tool_error", "tool_error")
                } else {
                    ("success", "success")
                }
            }
            Err(e) if matches!(self.phase, "not_admitted" | "admitted") => (e.0, "not_submitted"),
            Err(e) => (e.0, "unknown"),
            _ => ("tool_outcome_unknown", "unknown"),
        }
    }
}

fn unavailable(id: &str, phase: &'static str) {
    tracing::warn!(operation_id = id, phase, "native_diagnostic_unavailable");
}

impl Drop for Trace {
    fn drop(&mut self) {
        if !self.done {
            tracing::warn!(
                operation_id = self.id,
                phase = self.phase,
                "native_operation_interrupted"
            );
        }
    }
}

fn diagnostic_deadline(control: &Control) -> tokio::time::Instant {
    control
        .deadline
        .min(tokio::time::Instant::now() + std::time::Duration::from_millis(50))
}
