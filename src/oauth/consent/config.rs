use super::{Error, Result, digest, identifier};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub callback: Callback,
    pub profiles: Vec<Profile>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Callback {
    pub address: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub kind: String,
    pub client_id: String,
    pub client_generation: u64,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub resource: String,
    pub redirect_profile_id: String,
    pub redirect_uri: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expected_workspace: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expected_user: String,
    pub ca_path: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<super::contract::Contract>,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if !self.callback.address.ip().is_loopback()
            || self.callback.address.port() == 0
            || !matches!(
                self.callback.address.ip().to_string().as_str(),
                "127.0.0.1" | "::1"
            )
            || self.profiles.is_empty()
            || self.profiles.len() > 8
        {
            return Err(Error("invalid_profile"));
        }
        let mut ids = HashSet::new();
        for p in &self.profiles {
            p.validate()?;
            if !ids.insert(&p.id)
                || (!p.hosted()
                    && !p.slack()
                    && !p.custom()
                    && p.redirect_uri
                        != format!("https://{}/oauth/callback", self.callback.address))
            {
                return Err(Error("invalid_profile"));
            }
        }
        super::callback_route::validate(&self.profiles)
    }
}
impl Profile {
    pub(crate) fn custom(&self) -> bool {
        self.kind == "custom-oauth-v1"
    }
    pub(crate) fn confidential(&self) -> bool {
        self.slack()
            || self
                .contract
                .as_ref()
                .is_some_and(|c| c.client_auth == "client_secret_post")
    }
    pub(crate) fn hosted(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "linear-hosted-v1" | "linear-hosted-fixture-v1"
        )
    }
    pub(crate) fn stored_kind(&self) -> &'static str {
        match self.kind.as_str() {
            "custom-oauth-v1" => "custom_oauth_v1",
            "controlled-linear-v1" => "controlled_linear_v1",
            "linear-hosted-v1" => "linear_hosted_v1",
            "linear-hosted-fixture-v1" => "linear_hosted_fixture_v1",
            "slack-confidential-v1" => "slack_confidential_v1",
            "slack-confidential-fixture-v1" => "slack_confidential_fixture_v1",
            _ => "invalid",
        }
    }
    pub(crate) fn auth_spec(&self) -> crate::registrations::AuthSpec {
        crate::registrations::AuthSpec::OauthPkce {
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scopes: self.scopes(),
            auth_url: self.authorization_endpoint.clone(),
            token_url: self.token_endpoint.clone(),
            session_label: None,
        }
    }
    pub fn digest(&self) -> Result<String> {
        Ok(digest(
            &serde_json::to_vec(self).map_err(|_| Error("invalid_profile"))?,
        ))
    }
    fn validate(&self) -> Result<()> {
        if self.custom() {
            return super::contract::validate(self);
        }
        if self.contract.is_some() {
            return Err(Error("invalid_profile"));
        }
        if self.slack() {
            return super::slack::validate(self);
        }
        if !identifier(&self.id)
            || !identifier(&self.redirect_profile_id)
            || (!self.hosted() && self.kind != "controlled-linear-v1")
            || self.client_generation == 0
            || self.client_id.is_empty()
            || self.client_id.len() > 256
            || !self.client_id.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || !uuid(&self.expected_workspace)
            || !uuid(&self.expected_user)
        {
            return Err(Error("invalid_profile"));
        }
        if self.hosted() {
            let mut names = HashSet::new();
            if self.selected_tools.is_empty()
                || self.selected_tools.len() > 32
                || self.selected_tools.iter().any(|n| {
                    n.is_empty()
                        || n.len() > 128
                        || n.chars().any(char::is_control)
                        || !names.insert(n)
                })
            {
                return Err(Error("invalid_profile"));
            }
            https(&self.redirect_uri, "/oauth/callback")?;
            if self.kind == "linear-hosted-v1" {
                if self.issuer != "https://mcp.linear.app"
                    || self.authorization_endpoint != "https://mcp.linear.app/authorize"
                    || self.token_endpoint != "https://mcp.linear.app/token"
                    || self.resource != "https://mcp.linear.app/mcp/readonly"
                {
                    return Err(Error("invalid_profile"));
                }
                return Ok(());
            }
        } else if !self.selected_tools.is_empty() {
            return Err(Error("invalid_profile"));
        }
        let issuer = endpoint(&self.issuer, "/")?;
        if self.issuer != issuer.origin().ascii_serialization() {
            return Err(Error("invalid_profile"));
        }
        for (url, path) in [
            (&self.authorization_endpoint, "/authorize"),
            (&self.token_endpoint, "/token"),
        ] {
            if endpoint(url, path)?.origin() != issuer.origin() {
                return Err(Error("invalid_profile"));
            }
        }
        let resource = endpoint(&self.resource, "/mcp/readonly")?;
        if self.hosted() {
            if resource.origin() != issuer.origin() {
                return Err(Error("invalid_profile"));
            }
        } else {
            endpoint(&self.redirect_uri, "/oauth/callback")?;
        }
        Ok(())
    }
}
pub(super) use super::config_values::managed_kind;
use super::config_values::uuid;
pub(super) use super::config_values::{endpoint, https};

#[cfg(test)]
#[path = "config_tests.rs"]
mod hosted_tests;
