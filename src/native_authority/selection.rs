//! Deliberate owner delegation using the existing binding and custody tables.
use super::{Error, Result, runtime::Runtime, source::Current, store};
use crate::registrations::{AuthSpec, Protocol};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};

pub(super) fn custody(e: crate::oauth::consent::Error) -> Error {
    Error(match e.0 {
        "custody_failed" | "sealing_failed" => "oauth_custody_unavailable",
        "not_found" => "not_found",
        "source_conflict" => "source_conflict",
        "access_expired" => "access_expired",
        _ => "controlled_account_unavailable",
    })
}
impl Runtime {
    pub(super) fn current_roots(
        &self,
        current: &Current,
    ) -> Vec<locksmith_mcp_transport::Certificate> {
        current
            .controlled
            .as_ref()
            .map(|a| a.roots.clone())
            .unwrap_or_else(|| self.roots.clone())
    }
    // Owner authorization is read in the SAME transaction as current authority.
    // Test/legacy administrative callers without an owner cannot access controlled rows.
    pub(super) async fn current_for(
        &self,
        c: &mut SqliteConnection,
        owner: Option<&str>,
        agent: &str,
        name: &str,
    ) -> Result<Current> {
        let raw:Option<String>=sqlx::query_scalar("SELECT b.auth_spec FROM agent_credential_overrides b JOIN agents a ON a.id=b.agent_id WHERE a.public_id=? AND b.registration=?")
            .bind(agent).bind(name).fetch_optional(&mut *c).await?;
        if let Some(raw) = raw {
            let auth: AuthSpec =
                serde_json::from_str(&raw).map_err(|_| Error("source_unavailable"))?;
            if let AuthSpec::ControlledOauth { owner_id, .. } = auth
                && owner != Some(owner_id.as_str())
            {
                return Err(Error("not_found"));
            }
        }
        self.current(c, agent, name).await
    }
    pub async fn select_oauth(
        &self,
        owner: &str,
        agent: &str,
        name: &str,
        label: &str,
        expected: &str,
    ) -> Result<Value> {
        let consent = self
            .consent
            .as_ref()
            .ok_or(Error("oauth_custody_unavailable"))?;
        let mut tx = self.repo.pool.begin_with("BEGIN IMMEDIATE").await?;
        let selection = consent
            .native_selection(&mut tx, owner, name, label, expected)
            .await
            .map_err(custody)?;
        let row = sqlx::query("SELECT id,public_id,name FROM agents WHERE public_id=?")
            .bind(agent)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error("agent_not_found"))?;
        let identity = crate::auth_v2::AgentIdentity {
            id: row.get("id"),
            public_id: row.get("public_id"),
            name: row.get("name"),
            tool_allowlist: None,
            tool_denylist: None,
        };
        let mut rows = self
            .repo
            .admissions_on(&mut tx, &identity, Some(name), Protocol::McpStreamableHttp)
            .await
            .map_err(|_| Error("backend_unavailable"))?;
        let admission = rows.pop().ok_or(Error("source_unavailable"))?;
        if !admission.agent_active
            || admission.grant.is_err()
            || crate::registrations::admission::activation(
                &admission.registration,
                Some(&self.catalog.load_full()),
            ) != "active"
        {
            return Err(Error("connection_not_allowed"));
        }
        crate::definitions::eligibility::selected(
            &mut tx,
            &admission.registration,
            Some(&selection),
        )
        .await
        .map_err(|_| Error("definition_unavailable"))?;
        let auth = serde_json::to_string(&selection).map_err(|_| Error("source_unavailable"))?;
        // Re-selection is deliberate repair, even for the same stamp. Reuse the
        // existing deletion triggers so no prior finite grants survive silently.
        sqlx::query("DELETE FROM agent_credential_overrides WHERE agent_id=? AND registration=?")
            .bind(identity.id)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO agent_credential_overrides(agent_id,registration,auth_spec,created_at,updated_at) VALUES(?,?,?,?,?)")
            .bind(identity.id).bind(name).bind(auth).bind(store::now()).bind(store::now()).execute(&mut *tx).await?;
        let current = self.current_for(&mut tx, Some(owner), agent, name).await?;
        current.fresh()?;
        let result = json!({"source":current.source,"selection":selection,"requires_observation":true,"callable":false});
        tx.commit().await?;
        Ok(result)
    }
}
