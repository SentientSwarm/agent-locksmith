//! AdminService: cross-transport business logic for admin operations.
//! C-12 (SPEC §4.2.14). Verification gate per §6.4.1.

use crate::auth_v2::{AgentIdentity, OperatorIdentity};
use crate::repo::{
    AgentRecord, AgentRepository, BootstrapScope, BootstrapTokenRecord, BootstrapTokenRepository,
    RepoError,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

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
}

impl AdminService {
    pub fn new(
        agents: AgentRepository,
        bootstrap: BootstrapTokenRepository,
        config: std::sync::Arc<arc_swap::ArcSwap<crate::config::AppConfig>>,
    ) -> Self {
        Self {
            agents,
            bootstrap,
            config,
        }
    }

    // ─── Agent self-service ────────────────────────────────────────

    /// Register a new agent. The bootstrap token is consumed atomically
    /// with the agent insert; if the agent name conflicts, the bootstrap
    /// is NOT consumed (INF-10). Returns the cleartext agent token —
    /// returned exactly once per R-N4.
    pub async fn register_agent(&self, input: RegisterInput) -> Result<RegisterOutput, AdminError> {
        // Parse the bootstrap token to extract its public_id.
        let raw = input.bootstrap_token.expose_secret();
        let (ns, public_id, secret) =
            crate::token::parse(raw).map_err(|_| AdminError::InvalidBootstrap)?;
        if !matches!(ns, crate::token::TokenNamespace::Bootstrap) {
            return Err(AdminError::InvalidBootstrap);
        }

        // Pre-fetch the bootstrap scope so we know what allowlist to
        // apply on the agent without consuming the token yet (INF-10:
        // bootstrap NOT consumed if agent name conflicts).
        let scope_preview = self.bootstrap.preview_scope(public_id.as_str()).await?;
        let allowlist_owned = scope_preview.tool_allowlist.clone();
        let allowlist_slice = allowlist_owned.as_deref();

        // Now create the agent. If this fails (name conflict), the
        // bootstrap stays unused.
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

        // Now consume the bootstrap (also verifies the secret).
        let secret_str = SecretString::from(secret.expose().to_string());
        let consumed = self
            .bootstrap
            .consume(public_id.as_str(), &secret_str, agent.id)
            .await;
        if let Err(e) = consumed {
            // Bootstrap consume failed AFTER agent create succeeded —
            // roll back the agent so the operator can retry without a
            // dangling registration.
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
        let new_secret = self.agents.rotate(&agent.public_id, current_secret).await?;
        Ok(RotateOutput {
            public_id: agent.public_id.clone(),
            token: format!("lk_{}.{}", agent.public_id, new_secret.expose_secret()),
        })
    }

    pub async fn deregister_agent(&self, agent: &AgentIdentity) -> Result<(), AdminError> {
        self.agents.revoke(&agent.public_id).await?;
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
                credential_present: matches!(&t.auth, Some(a) if !a.value.expose_secret().is_empty())
                    || t.auth.is_none(),
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
        _op: &OperatorIdentity,
        input: CreateAgentInput,
    ) -> Result<RegisterOutput, AdminError> {
        let allowlist_slice = input.allowlist.as_deref();
        let denylist_slice = input.denylist.as_deref();
        let (pid, secret) = self
            .agents
            .create(
                &input.name,
                input.description.as_deref(),
                allowlist_slice,
                denylist_slice,
                input.metadata.as_ref(),
                input.expires_at,
            )
            .await?;
        Ok(RegisterOutput {
            public_id: pid.clone(),
            token: format!("lk_{}.{}", pid, secret.expose_secret()),
            allowlist: input.allowlist,
        })
    }

    pub async fn modify_agent(
        &self,
        _op: &OperatorIdentity,
        public_id: &str,
        input: ModifyAgentInput,
    ) -> Result<(), AdminError> {
        self.agents
            .update_policy(
                public_id,
                input.allowlist,
                input.denylist,
                input.metadata,
                input.expires_at,
            )
            .await?;
        Ok(())
    }

    pub async fn revoke_agent(
        &self,
        _op: &OperatorIdentity,
        public_id: &str,
    ) -> Result<(), AdminError> {
        self.agents.revoke(public_id).await?;
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
        let (pid, secret) = self.bootstrap.mint(scope.clone(), &op.name).await?;
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
        _op: &OperatorIdentity,
        public_id: &str,
    ) -> Result<(), AdminError> {
        self.bootstrap.revoke(public_id).await?;
        Ok(())
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
                credential_present: matches!(&t.auth, Some(a) if !a.value.expose_secret().is_empty())
                    || t.auth.is_none(),
            })
            .collect())
    }
}
