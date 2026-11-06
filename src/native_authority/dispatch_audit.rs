use super::{
    Error, Result, control::Control, diagnostics::Trace, dispatch::Invocation, effective::Snapshot,
    runtime::Runtime, store,
};
use crate::repo::audit::{AuditEvent, AuditRepository, Decision, EventClass};
use serde_json::json;

impl Runtime {
    pub(super) async fn commit_call(
        &self,
        call: &Invocation,
        before: &Snapshot,
        control: &Control,
        audit: &AuditRepository,
        trace: &mut Trace,
    ) -> Result<()> {
        control.check()?;
        let mut tx = self.repo.pool.begin_with("BEGIN IMMEDIATE").await?;
        self.recheck(&mut tx, call, before).await?;
        let event = event(call, &trace.id);
        control.check()?;
        audit
            .insert_on(&mut tx, &event)
            .await
            .map_err(|_| Error("admission_audit_failed"))?;
        // INSERT can wait. Recompute time-based lifecycle/freshness before COMMIT.
        self.recheck(&mut tx, call, before).await?;
        control.check()?;
        trace.commit_submitted(&event);
        tx.commit()
            .await
            .map_err(|_| Error("admission_commit_failed"))?;
        trace.admitted(event);
        Ok(())
    }
    async fn recheck(
        &self,
        tx: &mut sqlx::SqliteConnection,
        call: &Invocation,
        before: &Snapshot,
    ) -> Result<()> {
        let current = self.effective(tx, &call.agent, &call.connection).await?;
        current.matches(before)?;
        current.tool(&call.name, &call.digest)?;
        Ok(())
    }
}
fn event(call: &Invocation, id: &str) -> AuditEvent {
    AuditEvent {
        ts_ms: store::now() * 1000,
        event_class: EventClass::Security,
        event: "mcp_admitted".into(),
        agent_public_id: Some(call.agent.clone()),
        tool: Some(call.connection.clone()),
        decision: Decision::Allowed,
        details: Some(
            json!({"admission_id":id,"operation_id":id,"tool_name":call.name,"contract_digest":call.digest,
            "source":call.source,"retry":"never"}),
        ),
        ..Default::default()
    }
}
