//! One SQLite statement is the admission boundary: current agent policy/lifecycle,
//! connection and selected account are read from the same database snapshot.
use super::{AuthSpec, Catalog, Kind, Registration, RegistrationRepository, repo};
use crate::auth_v2::AgentIdentity;
use sqlx::Row;

pub struct HttpAdmission {
    pub registration: Registration,
    pub account: Option<AuthSpec>,
    pub agent_active: bool,
    pub grant: Result<(), &'static str>,
}

#[derive(Debug)]
pub struct AdmissionUnavailable;

impl RegistrationRepository {
    pub async fn http_admissions(
        &self,
        identity: &AgentIdentity,
        name: Option<&str>,
    ) -> Result<Vec<HttpAdmission>, AdmissionUnavailable> {
        let rows = sqlx::query(
            "SELECT r.*, a.id AS current_agent_id, \
             a.revoked_at, a.expires_at, a.grants_reviewed, a.tool_allowlist, a.tool_denylist, \
             b.auth_spec AS selected_auth \
             FROM registrations r \
             LEFT JOIN agents a ON a.id = ? AND a.public_id = ? \
             LEFT JOIN agent_credential_overrides b ON b.agent_id = a.id AND b.registration = r.name \
             WHERE (? IS NULL OR r.name = ?) AND r.kind IN ('tool', 'model') ORDER BY r.name",
        )
        .bind(identity.id).bind(&identity.public_id).bind(name).bind(name)
        .fetch_all(&self.pool).await.map_err(|_| AdmissionUnavailable)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let snapshots = rows.into_iter().map(|row| {
            let agent_active = row.get::<Option<i64>, _>("current_agent_id").is_some()
                && row.get::<Option<i64>, _>("revoked_at").is_none()
                && row
                    .get::<Option<i64>, _>("expires_at")
                    .is_none_or(|t| t > now);
            let reviewed = row
                .get::<Option<bool>, _>("grants_reviewed")
                .unwrap_or(false);
            let mut current = identity.clone();
            current.tool_allowlist = if reviewed {
                list(&row, "tool_allowlist")?
            } else {
                None
            };
            current.tool_denylist = list(&row, "tool_denylist")?;
            let name: String = row.get("name");
            let account = row
                .get::<Option<String>, _>("selected_auth")
                .map(|s| serde_json::from_str(&s).map_err(|_| AdmissionUnavailable))
                .transpose()?;
            Ok(HttpAdmission {
                registration: repo::row_to_registration(row).map_err(|_| AdmissionUnavailable)?,
                account,
                agent_active,
                grant: current.allows_tool(&name),
            })
        });
        if name.is_some() {
            snapshots.collect()
        } else {
            // Discovery can omit an unreadable entry without hiding unrelated
            // healthy connections. Direct admission still returns an error.
            Ok(snapshots.filter_map(Result::ok).collect())
        }
    }
}

fn list(
    row: &sqlx::sqlite::SqliteRow,
    name: &str,
) -> Result<Option<Vec<String>>, AdmissionUnavailable> {
    row.get::<Option<String>, _>(name)
        .map(|s| serde_json::from_str(&s).map_err(|_| AdmissionUnavailable))
        .transpose()
}

/// Full contents, not coarse timestamps. Shared by proxy, discovery and admin.
/// Active only attests runtime configuration; it says nothing about credentials.
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
