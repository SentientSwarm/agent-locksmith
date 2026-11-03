use crate::registrations::AuthSpec;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub id: i64,
    pub public_id: String,
    pub name: String,
    pub tool_allowlist: Option<Vec<String>>,
    pub tool_denylist: Option<Vec<String>>,
    pub cert_identity: Option<String>,
    pub registered_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct Registration {
    pub name: String,
    pub kind: String,
    pub upstream: String,
    pub egress: String,
    pub auth: Option<AuthSpec>,
    pub disabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub agent_id: i64,
    pub registration: String,
    pub action: String,
    pub reason: String,
    pub auth_spec: Option<AuthSpec>,
    pub selected: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Legacy {
    pub name: String,
    pub reason: String,
    pub shape: LegacyShape,
    pub reference: Option<AuthSpec>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyShape {
    None,
    Env,
    EnvTransformed,
    File,
    String,
    Unsupported,
    NotInventoried,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub format_version: u8,
    pub snapshot: String,
    pub agents: Vec<Agent>,
    pub registrations: Vec<RegistrationSummary>,
    pub entries: Vec<Entry>,
    pub legacy: Vec<Legacy>,
    pub notice: String,
}
#[derive(Debug, Serialize)]
pub(super) struct Binding {
    pub agent_id: i64,
    pub registration: String,
    pub auth: Option<AuthSpec>,
    pub created_at: i64,
    pub updated_at: i64,
}
#[derive(Debug, Serialize)]
pub(super) struct Stored {
    pub secret_ref: String,
    pub set_at: i64,
    pub tombstoned_at: Option<i64>,
}
#[derive(Debug, Serialize)]
pub(super) struct Session {
    pub name: String,
    pub session_label: String,
    pub degraded: bool,
    pub account_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}
#[derive(Debug, Serialize)]
pub(super) struct Snapshot {
    pub agents: Vec<Agent>,
    pub registrations: Vec<Registration>,
    pub bindings: Vec<Binding>,
    pub stored: Vec<Stored>,
    pub sessions: Vec<Session>,
    pub revision: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationSummary {
    pub name: String,
    pub kind: String,
    pub disabled: bool,
    pub auth_spec: Option<AuthSpec>,
}
