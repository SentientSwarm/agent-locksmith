//! Name and destination validation for registrations. Same rules across YAML seed, admin
//! PUT, and CLI dispatch. Run before any DB write so the failure surface
//! is uniform.

use super::{Kind, RegistrationError};

/// HTTP connections need a base URL; custody and request parameters live elsewhere.
/// Infra entries are not HTTP proxy connections and retain their existing contract.
pub fn validate_upstream(kind: Kind, upstream: &str) -> Result<(), RegistrationError> {
    if kind == Kind::Infra {
        return Ok(());
    }
    let url = reqwest::Url::parse(upstream).map_err(|_| RegistrationError::InvalidUpstream)?;
    let has_authority = upstream.split_once("://").is_some_and(|(_, rest)| {
        !rest.is_empty() && !rest.starts_with('/') && !rest.split('/').next().unwrap().contains('@')
    });
    if !has_authority
        || !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || upstream.trim() != upstream
        || upstream.chars().any(|c| c.is_control() || c == '\\')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RegistrationError::InvalidUpstream);
    }
    Ok(())
}

/// Reserved names that must not be registered. These conflict with locksmith's
/// own endpoint paths or are reserved for future use (`metrics`, `audit`).
pub const RESERVED_NAMES: &[&str] = &[
    "livez", "readyz", "version", "health", "skill", "tools", "models", "admin", "api", "metrics",
    "audit",
];

/// Maximum name length. Names appear in URL paths, audit rows, and human
/// log output — keep them short.
pub const MAX_NAME_LEN: usize = 64;

/// Validate a registration name. Same rules across all entry points.
///
/// - Charset: `[a-z0-9-]` (lowercase ASCII alnum + dash).
/// - Length: 1..=64.
/// - Not reserved.
pub fn validate_name(name: &str) -> Result<(), RegistrationError> {
    if name.is_empty() {
        return Err(RegistrationError::InvalidName("name is empty"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(RegistrationError::InvalidName("name exceeds 64 characters"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(RegistrationError::InvalidName(
            "name contains invalid characters (allowed: a-z 0-9 -)",
        ));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(RegistrationError::ReservedName);
    }
    Ok(())
}
