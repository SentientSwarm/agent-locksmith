//! Trusted operator selection. Provider data never selects the finite language.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy {
    #[default]
    #[serde(rename = "finite-v1")]
    V1,
    #[serde(rename = "finite-v2")]
    V2,
}
impl Policy {
    pub fn is_v1(&self) -> bool {
        *self == Self::V1
    }
}
pub const PUBLIC_MARKER: &str = "locksmith.dev/native-contract";
