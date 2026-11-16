//! A route's request policy (AGENT-281): which requests the route may
//! forward at all, independent of its wire [`super::RouteProfile`].
//!
//! Stored in `registrations.policy` with no CHECK constraint, so a new
//! policy needs no table rebuild. A stored value this build does not know
//! fails the route closed rather than forwarding without its policy.

use serde::{Deserialize, Serialize};

use super::RegistrationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutePolicy {
    /// Databento Historical: forward only the metadata API.
    #[serde(rename = "databento-historical")]
    DatabentoHistorical,
    /// A stored value this build does not know (written by a newer
    /// build). Never parsed from the API; the gate refuses every request.
    #[serde(rename = "unrecognized")]
    Unrecognized,
}

impl RoutePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DatabentoHistorical => "databento-historical",
            Self::Unrecognized => "unrecognized",
        }
    }

    /// Read a stored value; an unknown one fails the route closed.
    pub fn from_stored(s: &str) -> Self {
        s.parse().unwrap_or(Self::Unrecognized)
    }
}

impl std::str::FromStr for RoutePolicy {
    type Err = RegistrationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "databento-historical" => Ok(Self::DatabentoHistorical),
            _ => Err(RegistrationError::InvalidPolicy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_round_trip_and_reject_unknown() {
        let p = RoutePolicy::DatabentoHistorical;
        assert_eq!(p.as_str().parse::<RoutePolicy>().unwrap(), p);
        assert_eq!(
            serde_json::to_value(p).unwrap(),
            serde_json::json!("databento-historical")
        );
        assert!(matches!(
            "github-api".parse::<RoutePolicy>(),
            Err(RegistrationError::InvalidPolicy)
        ));
        assert!(matches!(
            "Databento-Historical".parse::<RoutePolicy>(),
            Err(RegistrationError::InvalidPolicy)
        ));
        assert!(matches!(
            "unrecognized".parse::<RoutePolicy>(),
            Err(RegistrationError::InvalidPolicy)
        ));
    }

    #[test]
    fn unknown_stored_value_is_unrecognized() {
        assert_eq!(
            RoutePolicy::from_stored("databento-historical"),
            RoutePolicy::DatabentoHistorical
        );
        assert_eq!(
            RoutePolicy::from_stored("github-api"),
            RoutePolicy::Unrecognized
        );
    }
}
