//! Current lifecycle, policy and selection are read from one SQLite snapshot.
use super::{AuthSpec, Catalog, Kind, Protocol, Registration, RegistrationRepository, repo};
use crate::auth_v2::AgentIdentity;
use sqlx::Row;

pub struct HttpAdmission {
    pub registration: Registration,
    pub account: Option<AuthSpec>,
    pub agent_active: bool,
    pub grant: Result<(), &'static str>,
    pub instance: String,
    pub revision: i64,
    pub epoch: i64,
}
#[derive(Debug)]
pub struct AdmissionUnavailable;

impl RegistrationRepository {
    pub async fn http_admissions(
        &self,
        identity: &AgentIdentity,
        name: Option<&str>,
    ) -> Result<Vec<HttpAdmission>, AdmissionUnavailable> {
        self.admissions(identity, name, Protocol::Http).await
    }
    pub async fn native_admissions(
        &self,
        identity: &AgentIdentity,
        name: Option<&str>,
    ) -> Result<Vec<HttpAdmission>, AdmissionUnavailable> {
        self.admissions(identity, name, Protocol::McpStreamableHttp)
            .await
    }
    async fn admissions(
        &self,
        identity: &AgentIdentity,
        name: Option<&str>,
        protocol: Protocol,
    ) -> Result<Vec<HttpAdmission>, AdmissionUnavailable> {
        let rows = sqlx::query(
            "SELECT r.*, a.id AS current_agent_id, a.mcp_epoch, \
             i.instance_id, i.revision, a.revoked_at, a.expires_at, a.grants_reviewed, \
             a.tool_allowlist, a.tool_denylist, b.auth_spec AS selected_auth \
             FROM registrations r JOIN registration_instances i ON i.name=r.name \
             LEFT JOIN agents a ON a.id = ? AND a.public_id = ? \
             LEFT JOIN agent_credential_overrides b ON b.agent_id=a.id AND b.registration=r.name \
             WHERE (? IS NULL OR r.name=?) AND r.protocol=? \
             AND r.kind IN ('tool','model') ORDER BY r.name",
        )
        .bind(identity.id)
        .bind(&identity.public_id)
        .bind(name)
        .bind(name)
        .bind(protocol.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AdmissionUnavailable)?;
        let snapshots = rows.into_iter().map(|row| snapshot(row, identity));
        if name.is_some() {
            snapshots.collect()
        } else {
            Ok(snapshots.filter_map(Result::ok).collect())
        }
    }
}
fn snapshot(
    row: sqlx::sqlite::SqliteRow,
    identity: &AgentIdentity,
) -> Result<HttpAdmission, AdmissionUnavailable> {
    let mut current = identity.clone();
    current.tool_allowlist = if row
        .get::<Option<bool>, _>("grants_reviewed")
        .unwrap_or(false)
    {
        list(&row, "tool_allowlist")?
    } else {
        None
    };
    current.tool_denylist = list(&row, "tool_denylist")?;
    Ok(HttpAdmission {
        grant: current.allows_tool(&row.get::<String, _>("name")),
        agent_active: active(&row),
        account: row
            .get::<Option<String>, _>("selected_auth")
            .map(|s| serde_json::from_str(&s).map_err(|_| AdmissionUnavailable))
            .transpose()?,
        instance: row.get("instance_id"),
        revision: row.get("revision"),
        epoch: row.get::<Option<i64>, _>("mcp_epoch").unwrap_or_default(),
        registration: repo::row_to_registration(row).map_err(|_| AdmissionUnavailable)?,
    })
}
fn active(row: &sqlx::sqlite::SqliteRow) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    row.get::<Option<i64>, _>("current_agent_id").is_some()
        && row.get::<Option<i64>, _>("revoked_at").is_none()
        && row
            .get::<Option<i64>, _>("expires_at")
            .is_none_or(|t| t > now)
}
fn list(
    row: &sqlx::sqlite::SqliteRow,
    name: &str,
) -> Result<Option<Vec<String>>, AdmissionUnavailable> {
    row.get::<Option<String>, _>(name)
        .map(|s| serde_json::from_str(&s).map_err(|_| AdmissionUnavailable))
        .transpose()
}
/// Full contents, not coarse timestamps. Activation is not credential readiness.
pub fn activation(registration: &Registration, catalog: Option<&Catalog>) -> &'static str {
    if registration.disabled {
        return "disabled";
    }
    if catalog
        .and_then(|c| c.lookup_any(&registration.name))
        .is_some_and(|r| r.as_ref() == registration)
    {
        "active"
    } else {
        "pending"
    }
}
impl HttpAdmission {
    pub fn discoverable(&self, kind: Kind, catalog: &Catalog) -> bool {
        self.agent_active
            && self.grant.is_ok()
            && self.registration.kind == kind
            && activation(&self.registration, Some(catalog)) == "active"
    }
}
