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
    pub expected_workspace: String,
    pub expected_user: String,
    pub ca_path: PathBuf,
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
                || p.redirect_uri != format!("https://{}/oauth/callback", self.callback.address)
            {
                return Err(Error("invalid_profile"));
            }
        }
        Ok(())
    }
}
impl Profile {
    pub fn digest(&self) -> Result<String> {
        Ok(digest(
            &serde_json::to_vec(self).map_err(|_| Error("invalid_profile"))?,
        ))
    }
    fn validate(&self) -> Result<()> {
        if !identifier(&self.id)
            || !identifier(&self.redirect_profile_id)
            || self.kind != "controlled-linear-v1"
            || self.client_generation == 0
            || self.client_id.is_empty()
            || self.client_id.len() > 256
            || !self.client_id.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || !uuid(&self.expected_workspace)
            || !uuid(&self.expected_user)
        {
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
        endpoint(&self.resource, "/mcp/readonly")?;
        endpoint(&self.redirect_uri, "/oauth/callback")?;
        Ok(())
    }
}
fn endpoint(raw: &str, path: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).map_err(|_| Error("invalid_profile"))?;
    if raw.len() > 2048
        || url.scheme() != "https"
        || !matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
        || url.port_or_known_default().is_none_or(|p| p == 0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != path
    {
        return Err(Error("invalid_profile"));
    }
    Ok(url)
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
