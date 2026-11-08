//! Missing issuer is permitted only at an issuer-distinct, state-bound Slack URI.
use super::{
    Error, Result,
    config::{Profile, https},
};
use std::collections::HashMap;

pub(super) const GENERIC: &str = "/oauth/callback";
pub(super) const SLACK: &str = "/oauth/callback/slack";

impl Profile {
    pub(super) fn callback_authority(&self) -> Result<String> {
        let url = self.callback_uri()?;
        Ok(url
            .origin()
            .ascii_serialization()
            .trim_start_matches("https://")
            .to_owned())
    }

    pub(super) fn callback_uri(&self) -> Result<reqwest::Url> {
        if let Some(c) = &self.contract {
            let path = if c.callback == "distinct_redirect" {
                format!("/oauth/callback/custom/{}", self.redirect_profile_id)
            } else {
                GENERIC.into()
            };
            return https(&self.redirect_uri, &path);
        }
        if self.slack()
            && let Ok(url) = https(&self.redirect_uri, SLACK)
        {
            return Ok(url);
        }
        https(&self.redirect_uri, GENERIC)
    }

    pub(super) fn check_callback(
        &self,
        issuer: Option<&str>,
        authority: &str,
        path: &str,
    ) -> Result<()> {
        let expected = self.callback_uri()?;
        if self.callback_authority()? != authority || expected.path() != path {
            return Err(Error("callback_refused"));
        }
        match issuer {
            Some(value) if value == self.issuer => Ok(()),
            None if self.slack() && path == SLACK => Ok(()),
            None if self
                .contract
                .as_ref()
                .is_some_and(|c| c.callback == "distinct_redirect") =>
            {
                Ok(())
            }
            _ => Err(Error("callback_refused")),
        }
    }
}

pub(super) fn validate(profiles: &[Profile]) -> Result<()> {
    let mut issuers = HashMap::new();
    for p in profiles {
        let uri = p.callback_uri()?;
        if uri.path() != GENERIC {
            // URL canonicalization includes host case and default port spelling.
            let key = (uri.origin().ascii_serialization(), uri.path().to_owned());
            if issuers
                .insert(key, &p.issuer)
                .is_some_and(|old| old != &p.issuer)
            {
                return Err(Error("invalid_profile"));
            }
        }
    }
    Ok(())
}
