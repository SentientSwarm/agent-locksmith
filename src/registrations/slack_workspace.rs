//! Verify sealed Slack tokens before committing them. Provider text is never echoed.
use super::{Kind, Protocol, Registration, RegistrationError};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use std::time::Duration;

pub fn expected(r: &Registration) -> Result<Option<&str>, RegistrationError> {
    match r.metadata.get("slack_team_id") {
        None => Ok(None),
        Some(value) => value.as_str().filter(|s| valid_team(s)).map(Some)
            .ok_or_else(|| RegistrationError::InvalidMetadata("slack_team_id must be a Slack team id (T followed by uppercase letters or digits)".into())),
    }
}
fn valid_team(s: &str) -> bool {
    (2..=64).contains(&s.len())
        && s.starts_with('T')
        && s.bytes()
            .skip(1)
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}
pub fn validate(r: &Registration) -> Result<(), RegistrationError> {
    if expected(r)?.is_some() && (r.kind != Kind::Tool || r.protocol != Protocol::Http) {
        return Err(RegistrationError::InvalidMetadata(
            "slack_team_id requires an HTTP tool route".into(),
        ));
    }
    Ok(())
}

/// Only fixed diagnostics and validated team ids can leave the provider boundary.
#[derive(Debug)]
pub struct Refusal {
    code: &'static str,
    expected: Option<String>,
    actual: Option<String>,
}
impl Refusal {
    pub(crate) fn code(&self) -> &'static str {
        self.code
    }
    fn failed() -> Self {
        Self {
            code: "slack_workspace_check_failed",
            expected: None,
            actual: None,
        }
    }
}
impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let mismatch = self.code == "slack_workspace_mismatch";
        let message = if mismatch {
            format!(
                "Slack workspace mismatch: expected {}, actual {}",
                self.expected.as_deref().unwrap_or_default(),
                self.actual.as_deref().unwrap_or_default()
            )
        } else {
            "Slack auth.test could not verify the token; nothing stored".into()
        };
        (if mismatch {StatusCode::BAD_REQUEST} else {StatusCode::BAD_GATEWAY},
         Json(json!({"error":{"code": self.code, "message":message, "expected_team_id":self.expected, "actual_team_id":self.actual}}))).into_response()
    }
}

/// No redirects, retries, provider error strings or unbounded response bodies.
/// A route with no workspace declaration keeps the existing offline ingestion.
pub async fn verify(
    r: &Registration,
    value: &SecretString,
    header: Option<&str>,
    config: Option<&crate::config::AppConfig>,
) -> Result<(), Refusal> {
    let Some(team) = expected(r).map_err(|_| Refusal::failed())? else {
        return Ok(());
    };
    // Slack workspace checks are bearer-only; accepting a custom header would
    // verify a different credential shape from the one later sent upstream.
    if header.is_some() {
        return Err(Refusal::failed());
    }
    let config = config.ok_or_else(Refusal::failed)?;
    let client = crate::client_pool::ClientPool::new()
        .get_or_build_for(
            &r.name,
            r.timeouts,
            r.egress,
            r.upstream_ca_pem.as_deref(),
            config,
        )
        .map_err(|_| Refusal::failed())?;
    let url = format!("{}/auth.test", r.upstream.trim_end_matches('/'));
    let mut response = client
        .post(url)
        .bearer_auth(value.expose_secret())
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|_| Refusal::failed())?;
    if !response.status().is_success() {
        return Err(Refusal::failed());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Refusal::failed())? {
        if bytes.len() + chunk.len() > 16384 {
            return Err(Refusal::failed());
        }
        bytes.extend_from_slice(&chunk);
    }
    let reply: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| Refusal::failed())?;
    if reply.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(Refusal::failed());
    }
    let actual = reply
        .get("team_id")
        .and_then(|v| v.as_str())
        .filter(|s| valid_team(s))
        .ok_or_else(Refusal::failed)?;
    if actual != team {
        return Err(Refusal {
            code: "slack_workspace_mismatch",
            expected: Some(team.into()),
            actual: Some(actual.into()),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn team_ids_are_bounded_safe_diagnostics() {
        for good in ["T1", "TABCDE123"] {
            assert!(valid_team(good));
        }
        for bad in [
            "T",
            "tABC",
            "T<script>",
            "T123\n",
            "T-xoxb-secret",
            &"T".repeat(65),
        ] {
            assert!(!valid_team(bad));
        }
    }
}
