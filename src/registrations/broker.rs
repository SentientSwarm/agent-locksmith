//! Brokered routes phase 3 — a destination that is an account broker.
//!
//! A broker holds, refreshes and picks the provider account itself.
//! Locksmith authenticates to it with one route-level key (the route's
//! auth template), names the calling agent in a header, and can copy the
//! broker's account label from the response into audit. Agents select a
//! broker route with the dedicated `broker` selection kind.

use serde::{Deserialize, Serialize};

use super::{AuthSpec, RegistrationError};

/// Header that names the calling agent (its public id) to the broker.
pub const DEFAULT_IDENTITY_HEADER: &str = "X-Locksmith-Agent";

const MAX_HEALTH_PATH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerSpec {
    /// Absent → [`DEFAULT_IDENTITY_HEADER`]; explicit `null` → none sent.
    #[serde(default = "default_identity_header")]
    pub identity_header: Option<String>,
    #[serde(default)]
    pub attribution: Option<Attribution>,
    #[serde(default)]
    pub health: Option<HealthProbe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    /// Response header whose value names the serving account.
    pub header: String,
    /// Record `sha256:<hex>` instead of the value.
    #[serde(default)]
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthProbe {
    pub path: String,
    #[serde(default = "default_expect_status")]
    pub expect_status: u16,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
}

fn default_identity_header() -> Option<String> {
    Some(DEFAULT_IDENTITY_HEADER.into())
}

fn default_expect_status() -> u16 {
    200
}

fn default_interval() -> u64 {
    30
}

impl Default for BrokerSpec {
    fn default() -> Self {
        Self {
            identity_header: default_identity_header(),
            attribution: None,
            health: None,
        }
    }
}

/// True for the auth shapes a broker key may take: a sealed or 1Password
/// value, sent as a bearer or a named header.
pub fn is_broker_key(auth: &AuthSpec) -> bool {
    matches!(
        auth,
        AuthSpec::StoredBearer { .. }
            | AuthSpec::StoredHeader { .. }
            | AuthSpec::OpBearer { .. }
            | AuthSpec::OpHeader { .. }
    )
}

/// Validate a broker spec against the route's key. Wire: 400
/// `invalid_broker`.
pub fn validate(spec: &BrokerSpec, auth: &AuthSpec) -> Result<(), RegistrationError> {
    let bad = |why: &str| Err(RegistrationError::InvalidBroker(why.into()));
    // `none` means "no key sealed yet": admission refuses until one is.
    if !is_broker_key(auth) && *auth != AuthSpec::None {
        return bad(
            "broker key must be none (unset), stored_bearer, stored_header, op_bearer or op_header",
        );
    }
    let key_header = auth.header_name().map(str::to_ascii_lowercase);
    if let Some(h) = &spec.identity_header {
        let lower = header_name(h)?;
        if matches!(lower.as_str(), "authorization" | "host") || Some(&lower) == key_header.as_ref()
        {
            return bad("identity_header must not be authorization, host or the key header");
        }
    }
    if let Some(a) = &spec.attribution {
        header_name(&a.header)?;
    }
    if let Some(p) = &spec.health {
        if !p.path.starts_with('/') || p.path.len() > MAX_HEALTH_PATH || p.path.contains(['?', '#'])
        {
            return bad("health.path must start with / and have no query or fragment");
        }
        if !(100..=599).contains(&p.expect_status) {
            return bad("health.expect_status must be 100-599");
        }
        if !(5..=3600).contains(&p.interval_seconds) {
            return bad("health.interval_seconds must be 5-3600");
        }
    }
    Ok(())
}

fn header_name(raw: &str) -> Result<String, RegistrationError> {
    axum::http::HeaderName::from_bytes(raw.as_bytes())
        .map(|h| h.as_str().to_string())
        .map_err(|_| RegistrationError::InvalidBroker("invalid header name".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AuthSpec {
        AuthSpec::StoredBearer {
            secret_ref: "cs_x".into(),
        }
    }

    #[test]
    fn identity_header_defaults_and_null_disables() {
        let d: BrokerSpec = serde_json::from_str("{}").unwrap();
        assert_eq!(d.identity_header.as_deref(), Some(DEFAULT_IDENTITY_HEADER));
        let n: BrokerSpec = serde_json::from_str(r#"{"identity_header":null}"#).unwrap();
        assert_eq!(n.identity_header, None);
        assert_eq!(d, BrokerSpec::default());
    }

    #[test]
    fn health_defaults() {
        let s: BrokerSpec = serde_json::from_str(r#"{"health":{"path":"/h"}}"#).unwrap();
        let h = s.health.unwrap();
        assert_eq!((h.expect_status, h.interval_seconds), (200, 30));
    }

    #[test]
    fn key_kinds() {
        assert!(validate(&BrokerSpec::default(), &key()).is_ok());
        assert!(validate(&BrokerSpec::default(), &AuthSpec::None).is_ok());
        for bad in [
            AuthSpec::Bearer {
                env_var: "K".into(),
            },
            AuthSpec::Broker,
        ] {
            assert!(validate(&BrokerSpec::default(), &bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unknown_fields_refused() {
        assert!(serde_json::from_str::<BrokerSpec>(r#"{"pool":1}"#).is_err());
    }
}
