//! AdminService: cross-transport business logic for admin operations.
//! C-12 (SPEC §4.2.14). Verification gate per §6.4.1.

use crate::auth_v2::{AgentIdentity, OperatorIdentity};
use crate::repo::audit::{
    AuditEvent, AuditFilter, AuditPage, AuditRepository, Decision, EventClass,
};
use crate::repo::{
    AgentRecord, AgentRepository, BootstrapScope, BootstrapStatus, BootstrapTokenRecord,
    BootstrapTokenRepository, RepoError,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("invalid bootstrap token")]
    InvalidBootstrap,
    #[error("agent name conflict")]
    AgentNameConflict,
    #[error("rotation in progress")]
    RotationInProgress,
    #[error("agent not found")]
    AgentNotFound,
    #[error("not authorized")]
    NotAuthorized,
    #[error("backend: {0}")]
    Backend(String),
}

impl From<RepoError> for AdminError {
    fn from(e: RepoError) -> Self {
        match e {
            RepoError::AgentNameConflict(_) => AdminError::AgentNameConflict,
            RepoError::RotationInProgress(_) => AdminError::RotationInProgress,
            RepoError::AgentNotFound => AdminError::AgentNotFound,
            RepoError::InvalidCredential => AdminError::InvalidBootstrap,
            other => AdminError::Backend(other.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterInput {
    pub bootstrap_token: SecretString,
    pub name: String,
    pub description: Option<String>,
    pub metadata: Option<Json>,
}

#[derive(Debug, Serialize)]
pub struct RegisterOutput {
    pub public_id: String,
    pub token: String,
    pub allowlist: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct AgentStatusOutput {
    pub public_id: String,
    pub name: String,
    pub description: Option<String>,
    pub allowlist: Option<Vec<String>>,
    pub denylist: Option<Vec<String>>,
    pub registered_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
}

impl From<AgentRecord> for AgentStatusOutput {
    fn from(r: AgentRecord) -> Self {
        Self {
            public_id: r.public_id,
            name: r.name,
            description: r.description,
            allowlist: r.tool_allowlist,
            denylist: r.tool_denylist,
            registered_at: r.registered_at,
            last_used_at: r.last_used_at,
            expires_at: r.expires_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RotateOutput {
    pub public_id: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateAgentInput {
    pub name: String,
    pub description: Option<String>,
    pub allowlist: Option<Vec<String>>,
    pub denylist: Option<Vec<String>>,
    pub metadata: Option<Json>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ModifyAgentInput {
    pub allowlist: Option<Option<Vec<String>>>,
    pub denylist: Option<Option<Vec<String>>>,
    pub metadata: Option<Option<Json>>,
    pub expires_at: Option<Option<i64>>,
}

#[derive(Debug, Deserialize)]
pub struct MintBootstrapInput {
    pub tool_allowlist: Option<Vec<String>>,
    pub expires_at: Option<i64>,
    #[serde(default = "yes")]
    pub single_use: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct MintBootstrapOutput {
    pub public_id: String,
    pub token: String,
    pub scope: BootstrapScope,
}

#[derive(Debug, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub egress: String,
    pub credential_present: bool,
}

#[derive(Clone)]
pub struct AdminService {
    agents: AgentRepository,
    bootstrap: BootstrapTokenRepository,
    config: std::sync::Arc<arc_swap::ArcSwap<crate::config::AppConfig>>,
    audit: Option<AuditRepository>,
    /// Resolved-credentials snapshot (M5). Used by tool listings to
    /// report `credential_present` against the runtime resolution
    /// state, not just the structural config. When `None`, fall back
    /// to `SecretRef::looks_present` (M2/M3 backward-compat).
    resolved_creds: Option<std::sync::Arc<arc_swap::ArcSwap<crate::secret::ResolvedCreds>>>,
}

impl AdminService {
    pub fn new(
        agents: AgentRepository,
        bootstrap: BootstrapTokenRepository,
        config: std::sync::Arc<arc_swap::ArcSwap<crate::config::AppConfig>>,
    ) -> Self {
        Self::with_audit(agents, bootstrap, config, None)
    }

    /// Construct an AdminService that records each state-mutating call
    /// to `audit`. Used by the daemon runtime; tests use this when they
    /// want to inspect emitted audit rows.
    pub fn with_audit(
        agents: AgentRepository,
        bootstrap: BootstrapTokenRepository,
        config: std::sync::Arc<arc_swap::ArcSwap<crate::config::AppConfig>>,
        audit: Option<AuditRepository>,
    ) -> Self {
        Self {
            agents,
            bootstrap,
            config,
            audit,
            resolved_creds: None,
        }
    }

    /// Full-power constructor: M5 daemon path supplies a resolved
    /// credentials snapshot so tool listings reflect the live
    /// resolution state.
    pub fn with_audit_and_creds(
        agents: AgentRepository,
        bootstrap: BootstrapTokenRepository,
        config: std::sync::Arc<arc_swap::ArcSwap<crate::config::AppConfig>>,
        audit: Option<AuditRepository>,
        resolved_creds: std::sync::Arc<arc_swap::ArcSwap<crate::secret::ResolvedCreds>>,
    ) -> Self {
        Self {
            agents,
            bootstrap,
            config,
            audit,
            resolved_creds: Some(resolved_creds),
        }
    }

    /// Returns true iff the named tool has a resolved credential. Used
    /// by `list_tools_for_*` to populate `credential_present`. Falls
    /// back to `SecretRef::looks_present` when no resolved-creds
    /// snapshot is wired (M2/M3 backward-compat).
    fn credential_present(&self, tool: &crate::config::ToolConfig) -> bool {
        let Some(auth) = &tool.auth else {
            return false;
        };
        if let Some(resolved) = &self.resolved_creds {
            return resolved.load().contains_key(&tool.name);
        }
        auth.value.looks_present()
    }

    /// Operator-context audit. Stamps `operator_name` from `op` (when
    /// not already set) and records the transport-level auth method:
    /// `op.auth_method` if Some (e.g. `"mtls"` from #83's cert path),
    /// otherwise the canonical `"operator"` label preserved from M2.
    async fn audit_for_operator(&self, op: &OperatorIdentity, mut event: AuditEvent) {
        if event.operator_name.is_none() {
            event.operator_name = Some(op.name.clone());
        }
        if event.auth_method.is_none() {
            event.auth_method = Some(op.auth_method.unwrap_or("operator").to_string());
        }
        self.audit(event).await;
    }

    /// Best-effort audit write. Errors are logged and swallowed (INF-26).
    /// Auto-fills `auth_method` (T6.10) based on whose context the event
    /// carries — operator_name → "operator", agent_public_id only →
    /// "agent" (self-service / bootstrap-register, where the
    /// bootstrap_token is the credential, not a long-lived agent token).
    /// Callers that already set auth_method are left alone.
    async fn audit(&self, mut event: AuditEvent) {
        let Some(repo) = &self.audit else {
            return;
        };
        if event.auth_method.is_none() {
            event.auth_method = Some(
                if event.operator_name.is_some() {
                    "operator"
                } else if event.event == "agent_register" {
                    // bootstrap-token register is the only agent-side
                    // path with no AgentIdentity context. Per D-10 it
                    // stands on its own as a distinct auth method.
                    "bootstrap"
                } else {
                    "agent"
                }
                .to_string(),
            );
        }
        if let Err(e) = repo.record(&event).await {
            tracing::warn!(error = %e, event = %event.event, "admin audit write failed");
        }
    }

    // ─── Agent self-service ────────────────────────────────────────

    /// Register a new agent. The bootstrap token is consumed atomically
    /// with the agent insert; if the agent name conflicts, the bootstrap
    /// is NOT consumed (INF-10). Returns the cleartext agent token —
    /// returned exactly once per R-N4.
    pub async fn register_agent(&self, input: RegisterInput) -> Result<RegisterOutput, AdminError> {
        // Pre-extract bootstrap public_id so we can emit a security
        // audit row on reuse (T3.4 / INF-13). Parse failures are also a
        // security event but we don't have a token id for them.
        let bootstrap_public_id = crate::token::parse(input.bootstrap_token.expose_secret())
            .ok()
            .filter(|(ns, _, _)| matches!(ns, crate::token::TokenNamespace::Bootstrap))
            .map(|(_, pid, _)| pid.as_str().to_string());

        let result = self.register_agent_inner(input).await;
        match &result {
            Ok(out) => {
                self.audit(AuditEvent {
                    ts_ms: now_ms(),
                    event_class: EventClass::Operator,
                    event: "agent_register".into(),
                    agent_public_id: Some(out.public_id.clone()),
                    decision: Decision::Allowed,
                    details: Some(json!({ "via": "bootstrap" })),
                    ..AuditEvent::default()
                })
                .await;
            }
            Err(e) => {
                // Distinguish bootstrap_reuse_attempt (security) from a
                // generic register failure (operator class). INF-13.
                let mut event_class = EventClass::Operator;
                let mut event_name = "agent_register".to_string();
                if matches!(e, AdminError::InvalidBootstrap)
                    && let Some(pid) = bootstrap_public_id.as_deref()
                    && let Ok(status) = self.bootstrap.diagnose(pid).await
                    && matches!(status, BootstrapStatus::Used | BootstrapStatus::Revoked)
                {
                    event_class = EventClass::Security;
                    event_name = "bootstrap_reuse_attempt".to_string();
                }
                self.audit(AuditEvent {
                    ts_ms: now_ms(),
                    event_class,
                    event: event_name,
                    decision: Decision::Denied,
                    details: Some(json!({
                        "error": e.to_string(),
                        "bootstrap_public_id": bootstrap_public_id,
                    })),
                    ..AuditEvent::default()
                })
                .await;
            }
        }
        result
    }

    async fn register_agent_inner(
        &self,
        input: RegisterInput,
    ) -> Result<RegisterOutput, AdminError> {
        let raw = input.bootstrap_token.expose_secret();
        let (ns, public_id, secret) =
            crate::token::parse(raw).map_err(|_| AdminError::InvalidBootstrap)?;
        if !matches!(ns, crate::token::TokenNamespace::Bootstrap) {
            return Err(AdminError::InvalidBootstrap);
        }

        let scope_preview = self.bootstrap.preview_scope(public_id.as_str()).await?;
        let allowlist_owned = scope_preview.tool_allowlist.clone();
        let allowlist_slice = allowlist_owned.as_deref();

        let (agent_pid, agent_secret) = self
            .agents
            .create(
                &input.name,
                input.description.as_deref(),
                allowlist_slice,
                None,
                input.metadata.as_ref(),
                None,
            )
            .await?;
        let agent = self
            .agents
            .get_active_by_public_id(&agent_pid)
            .await?
            .ok_or(AdminError::AgentNotFound)?;

        let secret_str = SecretString::from(secret.expose().to_string());
        let consumed = self
            .bootstrap
            .consume(public_id.as_str(), &secret_str, agent.id)
            .await;
        if let Err(e) = consumed {
            let _ = self.agents.revoke(&agent_pid).await;
            return Err(e.into());
        }

        Ok(RegisterOutput {
            public_id: agent_pid,
            token: format!("lk_{}.{}", agent.public_id, agent_secret.expose_secret()),
            allowlist: scope_preview.tool_allowlist,
        })
    }

    pub async fn get_agent_status(
        &self,
        agent: &AgentIdentity,
    ) -> Result<AgentStatusOutput, AdminError> {
        let record = self
            .agents
            .get_active_by_public_id(&agent.public_id)
            .await?
            .ok_or(AdminError::AgentNotFound)?;
        Ok(record.into())
    }

    pub async fn rotate_agent(
        &self,
        agent: &AgentIdentity,
        current_secret: &SecretString,
    ) -> Result<RotateOutput, AdminError> {
        let result = self.agents.rotate(&agent.public_id, current_secret).await;
        let event = match &result {
            Ok(_) => AuditEvent {
                ts_ms: now_ms(),
                event_class: EventClass::Operator,
                event: "agent_rotate".into(),
                agent_public_id: Some(agent.public_id.clone()),
                decision: Decision::Allowed,
                ..AuditEvent::default()
            },
            Err(e) => AuditEvent {
                ts_ms: now_ms(),
                event_class: EventClass::Operator,
                event: "agent_rotate".into(),
                agent_public_id: Some(agent.public_id.clone()),
                decision: Decision::Denied,
                details: Some(json!({ "error": e.to_string() })),
                ..AuditEvent::default()
            },
        };
        self.audit(event).await;
        let new_secret = result?;
        Ok(RotateOutput {
            public_id: agent.public_id.clone(),
            token: format!("lk_{}.{}", agent.public_id, new_secret.expose_secret()),
        })
    }

    pub async fn deregister_agent(&self, agent: &AgentIdentity) -> Result<(), AdminError> {
        // Self-revocation changes the agent's trust posture → Security
        // class per T3.11 review.
        let result = self.agents.revoke(&agent.public_id).await;
        self.audit(AuditEvent {
            ts_ms: now_ms(),
            event_class: EventClass::Security,
            event: "agent_deregister".into(),
            agent_public_id: Some(agent.public_id.clone()),
            decision: if result.is_ok() {
                Decision::Allowed
            } else {
                Decision::Denied
            },
            details: result
                .as_ref()
                .err()
                .map(|e| json!({ "error": e.to_string() })),
            ..AuditEvent::default()
        })
        .await;
        result?;
        Ok(())
    }

    pub async fn list_tools_for_agent(
        &self,
        agent: &AgentIdentity,
    ) -> Result<Vec<ToolInfo>, AdminError> {
        let cfg = self.config.load();
        let tools = cfg
            .tools
            .iter()
            .filter(|t| {
                let allowed = match &agent.tool_allowlist {
                    None => true,
                    Some(list) => list.iter().any(|n| n == &t.name),
                };
                let not_denied = match &agent.tool_denylist {
                    None => true,
                    Some(list) => !list.iter().any(|n| n == &t.name),
                };
                allowed && not_denied
            })
            .map(|t| ToolInfo {
                name: t.name.clone(),
                description: t.description.clone(),
                egress: match t.egress {
                    crate::config::EgressMode::Direct => "direct".into(),
                    crate::config::EgressMode::Proxied => "proxied".into(),
                },
                credential_present: self.credential_present(t) || t.auth.is_none(),
            })
            .collect();
        Ok(tools)
    }

    // ─── Operator ──────────────────────────────────────────────────

    pub async fn list_agents(
        &self,
        _op: &OperatorIdentity,
        include_revoked: bool,
    ) -> Result<Vec<AgentRecord>, AdminError> {
        Ok(self.agents.list(include_revoked).await?)
    }

    pub async fn get_agent(
        &self,
        _op: &OperatorIdentity,
        public_id_or_name: &str,
    ) -> Result<AgentRecord, AdminError> {
        if let Some(r) = self
            .agents
            .get_active_by_public_id(public_id_or_name)
            .await?
        {
            return Ok(r);
        }
        if let Some(r) = self.agents.get_by_name(public_id_or_name).await? {
            return Ok(r);
        }
        Err(AdminError::AgentNotFound)
    }

    pub async fn create_agent_as_operator(
        &self,
        op: &OperatorIdentity,
        input: CreateAgentInput,
    ) -> Result<RegisterOutput, AdminError> {
        let allowlist_slice = input.allowlist.as_deref();
        let denylist_slice = input.denylist.as_deref();
        let result = self
            .agents
            .create(
                &input.name,
                input.description.as_deref(),
                allowlist_slice,
                denylist_slice,
                input.metadata.as_ref(),
                input.expires_at,
            )
            .await;
        match &result {
            Ok((pid, _)) => {
                self.audit_for_operator(
                    op,
                    AuditEvent {
                        ts_ms: now_ms(),
                        event_class: EventClass::Operator,
                        event: "agent_create".into(),
                        agent_public_id: Some(pid.clone()),
                        decision: Decision::Allowed,
                        ..AuditEvent::default()
                    },
                )
                .await;
            }
            Err(e) => {
                self.audit_for_operator(
                    op,
                    AuditEvent {
                        ts_ms: now_ms(),
                        event_class: EventClass::Operator,
                        event: "agent_create".into(),
                        decision: Decision::Denied,
                        details: Some(json!({ "error": e.to_string(), "name": input.name })),
                        ..AuditEvent::default()
                    },
                )
                .await;
            }
        }
        let (pid, secret) = result?;
        Ok(RegisterOutput {
            public_id: pid.clone(),
            token: format!("lk_{}.{}", pid, secret.expose_secret()),
            allowlist: input.allowlist,
        })
    }

    pub async fn modify_agent(
        &self,
        op: &OperatorIdentity,
        public_id: &str,
        input: ModifyAgentInput,
    ) -> Result<(), AdminError> {
        let result = self
            .agents
            .update_policy(
                public_id,
                input.allowlist,
                input.denylist,
                input.metadata,
                input.expires_at,
            )
            .await;
        self.audit_for_operator(
            op,
            AuditEvent {
                ts_ms: now_ms(),
                event_class: EventClass::Operator,
                event: "agent_modify".into(),
                agent_public_id: Some(public_id.to_string()),
                decision: if result.is_ok() {
                    Decision::Allowed
                } else {
                    Decision::Denied
                },
                details: result
                    .as_ref()
                    .err()
                    .map(|e| json!({ "error": e.to_string() })),
                ..AuditEvent::default()
            },
        )
        .await;
        result?;
        Ok(())
    }

    pub async fn revoke_agent(
        &self,
        op: &OperatorIdentity,
        public_id: &str,
    ) -> Result<(), AdminError> {
        // Operator-driven revocation is a security-affecting event per
        // T3.11 review (changes the agent's trust posture).
        let result = self.agents.revoke(public_id).await;
        self.audit_for_operator(
            op,
            AuditEvent {
                ts_ms: now_ms(),
                event_class: EventClass::Security,
                event: "agent_revoke".into(),
                agent_public_id: Some(public_id.to_string()),
                decision: if result.is_ok() {
                    Decision::Allowed
                } else {
                    Decision::Denied
                },
                details: result
                    .as_ref()
                    .err()
                    .map(|e| json!({ "error": e.to_string() })),
                ..AuditEvent::default()
            },
        )
        .await;
        result?;
        Ok(())
    }

    pub async fn mint_bootstrap_token(
        &self,
        op: &OperatorIdentity,
        input: MintBootstrapInput,
    ) -> Result<MintBootstrapOutput, AdminError> {
        let scope = BootstrapScope {
            tool_allowlist: input.tool_allowlist,
            expires_at: input.expires_at,
            single_use: input.single_use,
        };
        let result = self.bootstrap.mint(scope.clone(), &op.name).await;
        let event = match &result {
            Ok((pid, _)) => AuditEvent {
                ts_ms: now_ms(),
                event_class: EventClass::Operator,
                event: "bootstrap_mint".into(),
                decision: Decision::Allowed,
                details: Some(json!({ "bootstrap_public_id": pid, "scope": &scope })),
                ..AuditEvent::default()
            },
            Err(e) => AuditEvent {
                ts_ms: now_ms(),
                event_class: EventClass::Operator,
                event: "bootstrap_mint".into(),
                decision: Decision::Denied,
                details: Some(json!({ "error": e.to_string() })),
                ..AuditEvent::default()
            },
        };
        self.audit_for_operator(op, event).await;
        let (pid, secret) = result?;
        Ok(MintBootstrapOutput {
            public_id: pid.clone(),
            token: format!("lkbt_{}.{}", pid, secret.expose_secret()),
            scope,
        })
    }

    pub async fn list_bootstrap_tokens(
        &self,
        _op: &OperatorIdentity,
    ) -> Result<Vec<BootstrapTokenRecord>, AdminError> {
        Ok(self.bootstrap.list().await?)
    }

    pub async fn revoke_bootstrap_token(
        &self,
        op: &OperatorIdentity,
        public_id: &str,
    ) -> Result<(), AdminError> {
        // Bootstrap revocation invalidates outstanding registration
        // capacity → Security class per T3.11 review.
        let result = self.bootstrap.revoke(public_id).await;
        self.audit_for_operator(
            op,
            AuditEvent {
                ts_ms: now_ms(),
                event_class: EventClass::Security,
                event: "bootstrap_revoke".into(),
                decision: if result.is_ok() {
                    Decision::Allowed
                } else {
                    Decision::Denied
                },
                details: Some(json!({
                    "bootstrap_public_id": public_id,
                    "error": result.as_ref().err().map(|e| e.to_string()),
                })),
                ..AuditEvent::default()
            },
        )
        .await;
        result?;
        Ok(())
    }

    /// Query the audit log. Operator-only (T3.6 / R-F7). Returns
    /// `AdminError::Backend("audit_disabled")` when the daemon was
    /// configured without an audit sink — operators get a clear signal
    /// rather than an empty result.
    pub async fn query_audit(
        &self,
        _op: &OperatorIdentity,
        filter: AuditFilter,
        page: AuditPage,
    ) -> Result<Vec<AuditEvent>, AdminError> {
        let Some(audit) = &self.audit else {
            return Err(AdminError::Backend("audit_disabled".into()));
        };
        Ok(audit.query(&filter, page).await?)
    }

    pub async fn list_tools_for_operator(
        &self,
        _op: &OperatorIdentity,
    ) -> Result<Vec<ToolInfo>, AdminError> {
        let cfg = self.config.load();
        Ok(cfg
            .tools
            .iter()
            .map(|t| ToolInfo {
                name: t.name.clone(),
                description: t.description.clone(),
                egress: match t.egress {
                    crate::config::EgressMode::Direct => "direct".into(),
                    crate::config::EgressMode::Proxied => "proxied".into(),
                },
                credential_present: self.credential_present(t) || t.auth.is_none(),
            })
            .collect())
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
