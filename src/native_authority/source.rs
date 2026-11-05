//! Recheck the existing coherent admission inside the caller's transaction.
use super::{Error, Result, contract};
use crate::{
    auth_v2::AgentIdentity,
    registrations::{AuthSpec, Catalog, Protocol, RegistrationRepository, admission},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub instance: String,
    pub revision: i64,
    pub account_key: String,
    pub agent_epoch: i64,
}
pub struct Current {
    pub source: Source,
    pub agent: i64,
    pub admission: admission::HttpAdmission,
    pub(crate) controlled: Option<crate::oauth::consent::native::Account>,
}
pub async fn current(
    repo: &RegistrationRepository,
    catalog: &Catalog,
    consent: Option<&crate::oauth::consent::Runtime>,
    connection: &mut SqliteConnection,
    public_id: &str,
    name: &str,
) -> Result<Current> {
    let identity = identity(connection, public_id).await?;
    let mut rows = repo
        .admissions_on(
            connection,
            &identity,
            Some(name),
            Protocol::McpStreamableHttp,
        )
        .await
        .map_err(|_| Error("source_unavailable"))?;
    let admission = rows.pop().ok_or(Error("source_unavailable"))?;
    active(&admission, catalog)?;
    let auth = admission
        .account
        .as_ref()
        .ok_or(Error("explicit_selection_required"))?;
    let controlled = if matches!(auth, AuthSpec::ControlledOauth { .. }) {
        Some(
            consent
                .ok_or(Error("oauth_custody_unavailable"))?
                .native_account(connection, name, auth)
                .await
                .map_err(super::selection::custody)?,
        )
    } else {
        supported(connection, auth).await?;
        None
    };
    let auth = auth.clone();
    let mut current = captured(identity.id, admission, auth.clone());
    if let Some(account) = &controlled {
        current.source.account_key = contract::digest(
            "locksmith-native-account-v2",
            &json!([
                current.source.instance,
                auth,
                account.version,
                account.roots_digest
            ]),
        );
    }
    current.controlled = controlled;
    current.fresh()?;
    Ok(current)
}
fn captured(agent: i64, admission: admission::HttpAdmission, auth: AuthSpec) -> Current {
    let account_key = contract::digest(
        "locksmith-native-account-v1",
        &json!([admission.instance, auth]),
    );
    let source = Source {
        instance: admission.instance.clone(),
        revision: admission.revision,
        account_key,
        agent_epoch: admission.epoch,
    };
    Current {
        source,
        agent,
        admission,
        controlled: None,
    }
}
async fn identity(connection: &mut SqliteConnection, public_id: &str) -> Result<AgentIdentity> {
    let row = sqlx::query("SELECT id,public_id,name FROM agents WHERE public_id=?")
        .bind(public_id)
        .fetch_optional(connection)
        .await?
        .ok_or(Error("agent_not_found"))?;
    Ok(AgentIdentity {
        id: row.get("id"),
        public_id: row.get("public_id"),
        name: row.get("name"),
        tool_allowlist: None,
        tool_denylist: None,
    })
}
async fn supported(connection: &mut SqliteConnection, auth: &AuthSpec) -> Result<()> {
    match auth {
        AuthSpec::None => Ok(()),
        AuthSpec::StoredBearer { secret_ref } => {
            let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM credential_secrets WHERE secret_ref=? AND tombstoned_at IS NULL)")
                .bind(secret_ref).fetch_one(connection).await?;
            if live {
                Ok(())
            } else {
                Err(Error("credential_unresolved"))
            }
        }
        _ => Err(Error("native_account_unsupported")),
    }
}
impl Current {
    pub fn fresh(&self) -> Result<()> {
        if self
            .controlled
            .as_ref()
            .and_then(|a| a.expires_at)
            .is_some_and(|t| t <= super::store::now())
        {
            Err(Error("access_expired"))
        } else {
            Ok(())
        }
    }
    pub fn scope(&self) -> String {
        let s = &self.source;
        let base = format!("{}:{}:{}", s.instance, s.revision, s.agent_epoch);
        if self.controlled.is_some() {
            format!("{base}:{}", s.account_key)
        } else {
            base
        }
    }

    pub fn matches(&self, expected: &Source) -> Result<()> {
        if &self.source == expected {
            Ok(())
        } else {
            Err(Error("source_conflict"))
        }
    }
}

fn active(admission: &admission::HttpAdmission, catalog: &Catalog) -> Result<()> {
    if !admission.agent_active
        || admission.grant.is_err()
        || admission.registration.definition_pinned()
        || admission::activation(&admission.registration, Some(catalog)) != "active"
    {
        return Err(Error("source_unavailable"));
    }
    Ok(())
}
