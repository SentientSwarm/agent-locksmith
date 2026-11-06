//! Protocol identity is typed configuration, never arbitrary metadata or authority.
use super::{Kind, RegistrationError, validate_upstream};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: &str = "2025-11-25";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Http,
    McpStreamableHttp,
}
impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::McpStreamableHttp => "mcp_streamable_http",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    pub protocol_version: String,
    #[serde(default)]
    pub allow_private_destination: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<crate::definitions::Pin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_activation: Option<crate::definitions::Activation>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub compact: bool,
    #[serde(
        default,
        skip_serializing_if = "crate::native_authority::policy::Policy::is_v1"
    )]
    pub contract_policy: crate::native_authority::policy::Policy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_tools: Option<Vec<String>>,
}

pub fn validate(
    protocol: Protocol,
    config: Option<&McpConfig>,
    kind: Kind,
    egress: crate::config::EgressMode,
    upstream: &str,
    metadata: Option<&Value>,
) -> Result<(), RegistrationError> {
    validate_upstream(kind, upstream)?;
    if protocol == Protocol::Http {
        return if config.is_none() {
            Ok(())
        } else {
            Err(RegistrationError::InvalidMcp)
        };
    }
    let config = config.ok_or(RegistrationError::InvalidMcp)?;
    if let Some(names) = &config.selected_tools {
        let mut seen = std::collections::BTreeSet::new();
        if config.contract_policy.is_v1()
            || names.is_empty()
            || names.len() > 32
            || names.iter().any(|n| {
                n.is_empty() || n.len() > 128 || n.chars().any(char::is_control) || !seen.insert(n)
            })
        {
            return Err(RegistrationError::InvalidMcp);
        }
    }
    let url = reqwest::Url::parse(upstream).map_err(|_| RegistrationError::InvalidMcp)?;
    if kind != Kind::Tool
        || egress != crate::config::EgressMode::Direct
        || config.protocol_version != VERSION
        || url.scheme() != "https"
        || metadata.is_some_and(|m| m.get("http_service").is_some())
        || (!config.allow_private_destination && private_host(&url))
    {
        return Err(RegistrationError::InvalidMcp);
    }
    Ok(())
}

fn private_host(url: &reqwest::Url) -> bool {
    let host = url
        .host_str()
        .unwrap_or("")
        .trim_matches(['[', ']'])
        .trim_end_matches('.');
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => private_v4(ip),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || ip.to_ipv4_mapped().is_some()
        }
        Err(_) => {
            host.is_empty()
                || host.eq_ignore_ascii_case("localhost")
                || host.ends_with(".localhost")
                || host.ends_with(".local")
        }
    }
}

/// Reject the explicitly configured local listener, without DNS side effects.
pub fn is_self(upstream: &str, host: &str, port: u16) -> bool {
    let Ok(url) = reqwest::Url::parse(upstream) else {
        return true;
    };
    let target = url
        .host_str()
        .unwrap_or("")
        .trim_matches(['[', ']'])
        .trim_end_matches('.');
    url.port_or_known_default() == Some(port)
        && (target.eq_ignore_ascii_case(host)
            || (["127.0.0.1", "::1", "localhost", "0.0.0.0", "::"].contains(&host)
                && ["127.0.0.1", "::1", "localhost"].contains(&target)))
}

fn private_v4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
}
