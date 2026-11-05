//! Strict descriptive data; none of these fields confer authority.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub schema_version: u32,
    pub id: String,
    pub revision: u32,
    pub name: String,
    pub summary: String,
    pub protocol_profiles: Vec<String>,
    pub auth_profiles: Vec<AuthProfile>,
    pub workflows: Vec<Workflow>,
    pub setup: String,
    pub limits: Vec<String>,
    pub verification: Verification,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthProfile {
    pub id: String,
    pub mechanism: Mechanism,
    pub setup: String,
    pub required_scopes: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    None,
    Header,
    Bearer,
    OauthProvider,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    pub id: String,
    pub summary: String,
    pub operations: Vec<String>,
    pub effect: Effect,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Read,
    Write,
    Mixed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub level: Level,
    pub evidence_ref: String,
    #[serde(deserialize_with = "Option::<String>::deserialize")]
    pub verified_at: Option<String>,
    #[serde(deserialize_with = "Option::<String>::deserialize")]
    pub source_revision: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Candidate,
    Fixture,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub id: String,
    pub revision: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub id: String,
    pub revision: u32,
    pub digest: String,
    pub auth_profile_id: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    pub definition: Reference,
    pub auth_profile_id: String,
    pub upstream: String,
    #[serde(default)]
    pub allow_private_destination: bool,
}
