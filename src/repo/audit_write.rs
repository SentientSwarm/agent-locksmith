use super::{AuditEvent, AuditRepository, RepoError};
impl AuditRepository {
    /// The caller owns COMMIT. Never mirrors uncommitted admission evidence.
    pub async fn insert_on(
        &self,
        connection: &mut sqlx::SqliteConnection,
        event: &AuditEvent,
    ) -> Result<(), RepoError> {
        let details = event
            .details
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        sqlx::query("INSERT INTO audit (ts,event_class,event,agent_public_id,operator_name,tool,upstream_host,method,path,status,latency_ms,decision,auth_method,origin_ip,details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(event.ts_ms).bind(event.event_class.as_str()).bind(&event.event)
            .bind(event.agent_public_id.as_deref()).bind(event.operator_name.as_deref())
            .bind(event.tool.as_deref()).bind(event.upstream_host.as_deref())
            .bind(event.method.as_deref()).bind(event.path.as_deref())
            .bind(event.status.map(i64::from)).bind(event.latency_ms.map(|v|v as i64))
            .bind(event.decision.as_str()).bind(event.auth_method.as_deref())
            .bind(event.origin_ip.as_deref()).bind(details).execute(connection).await?;
        Ok(())
    }
    /// Best effort, after the caller has successfully committed.
    pub async fn mirror(&self, event: &AuditEvent) {
        let _ = self.mirror_status(event).await;
    }
    pub async fn mirror_status(&self, event: &AuditEvent) -> crate::audit_sink::MirrorStatus {
        match &self.sink {
            Some(sink) => sink.append_status(event).await,
            None => crate::audit_sink::MirrorStatus::Absent,
        }
    }
    pub async fn record_status(
        &self,
        event: &AuditEvent,
    ) -> Result<crate::audit_sink::MirrorStatus, RepoError> {
        let mut connection = self.pool.acquire().await?;
        self.insert_on(&mut connection, event).await?;
        drop(connection);
        Ok(self.mirror_status(event).await)
    }
}
