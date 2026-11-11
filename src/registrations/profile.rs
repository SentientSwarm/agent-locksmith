//! Brokered routes phase 1 — a route's request profile.
//!
//! The profile selects provider wire behaviour (the Codex G2–G5 fixups)
//! instead of a substring of the upstream URL. A route without a stored
//! profile infers it from the upstream with the pre-0024 rule, so existing
//! routes keep their behaviour.

use serde::{Deserialize, Serialize};

use super::RegistrationError;

/// Request profile of a route. Stored as NULL when not set explicitly;
/// [`RouteProfile::effective`] supplies the inferred value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteProfile {
    #[serde(rename = "generic")]
    Generic,
    /// Codex Responses wire behaviour: G2 account header, G3/G5 body
    /// fixups and G4 required headers.
    #[serde(rename = "openai-codex-responses")]
    OpenaiCodexResponses,
}

impl RouteProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::OpenaiCodexResponses => "openai-codex-responses",
        }
    }

    /// The pre-0024 rule: a ChatGPT-plan Codex upstream path
    /// (`/backend-api/codex`, case-insensitive) means Codex behaviour.
    pub fn infer(upstream: &str) -> Self {
        if upstream.to_ascii_lowercase().contains("/backend-api/codex") {
            Self::OpenaiCodexResponses
        } else {
            Self::Generic
        }
    }

    /// An explicit profile wins; otherwise infer from the upstream.
    pub fn effective(stored: Option<Self>, upstream: &str) -> Self {
        stored.unwrap_or_else(|| Self::infer(upstream))
    }

    pub fn is_codex(self) -> bool {
        self == Self::OpenaiCodexResponses
    }
}

impl std::str::FromStr for RouteProfile {
    type Err = RegistrationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "generic" => Ok(Self::Generic),
            "openai-codex-responses" => Ok(Self::OpenaiCodexResponses),
            _ => Err(RegistrationError::InvalidProfile),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrations::RegistrationError;

    #[test]
    fn infer_matches_todays_codex_rule() {
        use RouteProfile::*;
        assert_eq!(
            RouteProfile::infer("https://chatgpt.com/backend-api/codex"),
            OpenaiCodexResponses
        );
        assert_eq!(
            RouteProfile::infer("HTTPS://CHATGPT.COM/BACKEND-API/CODEX/"),
            OpenaiCodexResponses
        );
        assert_eq!(
            RouteProfile::infer("http://127.0.0.1:1/backend-api/codex"),
            OpenaiCodexResponses
        );
        assert_eq!(RouteProfile::infer("https://api.openai.com/v1"), Generic);
        assert_eq!(RouteProfile::infer(""), Generic);
    }

    #[test]
    fn explicit_profile_beats_inference() {
        let codex = "https://chatgpt.com/backend-api/codex";
        assert_eq!(
            RouteProfile::effective(Some(RouteProfile::Generic), codex),
            RouteProfile::Generic
        );
        assert_eq!(
            RouteProfile::effective(None, codex),
            RouteProfile::OpenaiCodexResponses
        );
        assert_eq!(
            RouteProfile::effective(Some(RouteProfile::OpenaiCodexResponses), "http://broker:1"),
            RouteProfile::OpenaiCodexResponses
        );
    }

    #[test]
    fn wire_values_round_trip_and_reject_unknown() {
        for p in [RouteProfile::Generic, RouteProfile::OpenaiCodexResponses] {
            assert_eq!(p.as_str().parse::<RouteProfile>().unwrap(), p);
            assert_eq!(
                serde_json::to_value(p).unwrap(),
                serde_json::json!(p.as_str())
            );
        }
        assert_eq!(
            RouteProfile::OpenaiCodexResponses.as_str(),
            "openai-codex-responses"
        );
        assert!(matches!(
            "anthropic-messages".parse::<RouteProfile>(),
            Err(RegistrationError::InvalidProfile)
        ));
    }
}
