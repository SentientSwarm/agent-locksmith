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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_tools: Vec<String>,
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
                    && p.redirect_uri
                        != format!("https://{}/oauth/callback", self.callback.address))
            {
                return Err(Error("invalid_profile"));
            }
        }
        Ok(())
    }
}
impl Profile {
    pub(crate) fn hosted(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "linear-hosted-v1" | "linear-hosted-fixture-v1"
        )
    }
    pub(crate) fn stored_kind(&self) -> &'static str {
        match self.kind.as_str() {
            "controlled-linear-v1" => "controlled_linear_v1",
            "linear-hosted-v1" => "linear_hosted_v1",
            "linear-hosted-fixture-v1" => "linear_hosted_fixture_v1",
            _ => "invalid",
        }
    }
    pub(super) fn callback_authority(&self) -> Result<String> {
        let url = https(&self.redirect_uri, "/oauth/callback")?;
        Ok(url
            .origin()
            .ascii_serialization()
            .trim_start_matches("https://")
            .to_owned())
    }
    pub(crate) fn auth_spec(&self) -> crate::registrations::AuthSpec {
        crate::registrations::AuthSpec::OauthPkce {
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scopes: vec!["read".into()],
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
fn endpoint(raw: &str, path: &str) -> Result<reqwest::Url> {
    let url = https(raw, path)?;
    if !matches!(url.host_str(), Some("127.0.0.1" | "[::1]")) {
        return Err(Error("invalid_profile"));
    }
    Ok(url)
}
fn https(raw: &str, path: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).map_err(|_| Error("invalid_profile"))?;
    if raw.len() > 2048
        || url.scheme() != "https"
        || url.host_str().is_none()
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
pub(super) fn managed_kind(kind: &str) -> bool {
    matches!(
        kind,
        "controlled_linear_v1" | "linear_hosted_v1" | "linear_hosted_fixture_v1"
    )
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

#[cfg(test)]
mod hosted_tests {
    use super::*;
    use serde_json::{Value, json};
    fn configuration(kind: &str, origin: &str, redirect: &str) -> Value {
        let mut p = json!({"id":"test", "kind":kind, "client_id":"synthetic-client", "client_generation":1,
            "issuer":origin, "authorization_endpoint":format!("{origin}/authorize"),
            "token_endpoint":format!("{origin}/token"),"resource":format!("{origin}/mcp/readonly"),
            "redirect_profile_id":"callback", "redirect_uri":redirect,
            "expected_workspace":"00000000-0000-0000-0000-000000000041",
            "expected_user":"00000000-0000-0000-0000-000000000042","ca_path":"synthetic-ca.pem"});
        if kind != "controlled-linear-v1" {
            p["selected_tools"] = json!(["get_project", "get_issue"]);
        }
        json!({"callback":{"address":"127.0.0.1:24443","cert_path":"synthetic-cert.pem","key_path":"synthetic-key.pem"},"profiles":[p]})
    }
    fn valid(v: &Value) -> bool {
        serde_json::from_value::<Config>(v.clone()).is_ok_and(|c| c.validate().is_ok())
    }
    #[test]
    fn hosted_profiles_fixed_endpoints_public_callback_and_explicit_selection() {
        let controlled = configuration(
            "controlled-linear-v1",
            "https://127.0.0.1:24444",
            "https://127.0.0.1:24443/oauth/callback",
        );
        assert!(valid(&controlled), "unchanged controlled positive control");
        let hosted = configuration(
            "linear-hosted-v1",
            "https://mcp.linear.app",
            "https://callback.example.test/oauth/callback",
        );
        assert!(
            valid(&hosted),
            "fixed hosted profile with separately bound public callback"
        );
        let fixture = configuration(
            "linear-hosted-fixture-v1",
            "https://127.0.0.1:24444",
            "https://callback.example.test/oauth/callback",
        );
        assert!(
            valid(&fixture),
            "explicit offline twin uses shipping hosted policy"
        );
        for field in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "resource",
        ] {
            let mut wrong = hosted.clone();
            wrong["profiles"][0][field] = json!(format!("https://other.example/{}", field));
            assert!(!valid(&wrong), "{field}");
        }
        for uri in [
            "http://callback.example.test/oauth/callback",
            "https://user@callback.example.test/oauth/callback",
            "https://callback.example.test/oauth/callback?extra=1",
            "https://callback.example.test/other",
        ] {
            let mut wrong = hosted.clone();
            wrong["profiles"][0]["redirect_uri"] = json!(uri);
            assert!(!valid(&wrong));
        }
        for names in [
            json!([]),
            json!(["get_project", "get_project"]),
            json!([""]),
            json!(vec!["tool"; 33]),
        ] {
            let mut wrong = hosted.clone();
            wrong["profiles"][0]["selected_tools"] = names;
            assert!(!valid(&wrong));
        }
        let mut wrong = fixture.clone();
        wrong["profiles"][0]["issuer"] = json!("https://mcp.linear.app");
        assert!(!valid(&wrong));
        let mut wrong = controlled.clone();
        wrong["profiles"][0]["redirect_uri"] =
            json!("https://callback.example.test/oauth/callback");
        assert!(!valid(&wrong));
        let before: Profile = serde_json::from_value(controlled["profiles"][0].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(before).unwrap(),
            controlled["profiles"][0],
            "controlled serialization/digests cannot change"
        );
        let mut changed = hosted.clone();
        changed["profiles"][0]["selected_tools"] = json!(["get_project"]);
        let profile =
            |v: &Value| serde_json::from_value::<Profile>(v["profiles"][0].clone()).unwrap();
        assert_ne!(
            profile(&hosted).digest().unwrap(),
            profile(&changed).digest().unwrap()
        );
        assert_ne!(
            profile(&hosted).digest().unwrap(),
            profile(&fixture).digest().unwrap()
        );
    }
}
