//! Identity response fields are interpreted by their declared wire strategy.
use super::{
    super::{Error, Result, config::Profile},
    Subject,
};
use serde_json::Value;

pub(super) fn decode(p: &Profile, value: &Value) -> Result<Subject> {
    let c = p.contract.as_ref().ok_or(Error("invalid_profile"))?;
    let slack = c.identity.response == "slack-auth-test-v1";
    outcome(value, slack)?;
    let mut echoes = value.clone();
    if slack {
        display_team(&mut echoes)?;
    }
    super::token::echoes(p, &echoes).map_err(|e| match e.0 {
        "identity_mismatch" => Error("identity_echo_refused"),
        "token_metadata_mismatch" => Error("identity_metadata_refused"),
        _ => e,
    })?;
    required_subject(&c.subject, value, slack)?;
    c.subject
        .observe(value, slack)
        .map_err(|_| Error("identity_subject_mismatch"))
}

fn outcome(value: &Value, slack: bool) -> Result<()> {
    if !value.is_object() {
        return Err(Error("identity_response_shape"));
    }
    if ["error", "error_description", "error_uri"]
        .iter()
        .any(|k| value.get(k).is_some())
    {
        return Err(Error("identity_error_present"));
    }
    if slack && value.get("ok") != Some(&Value::Bool(true)) {
        return Err(Error("identity_ok_refused"));
    }
    if !slack && value.get("ok").is_some() {
        return Err(Error("identity_ok_unexpected"));
    }
    Ok(())
}

fn display_team(value: &mut Value) -> Result<()> {
    if let Some(team) = value.get("team") {
        if !team.is_string() {
            return Err(Error("identity_team_display_type"));
        }
        // auth.test team is a display label; team_id alone supplies identity.
        value.as_object_mut().unwrap().remove("team");
    }
    Ok(())
}

fn required_subject(subject: &Subject, value: &Value, slack: bool) -> Result<()> {
    let fields: &[(&str, &str)] = match subject {
        Subject::UserWorkspace { .. } => &[
            (
                if slack { "team_id" } else { "workspace_id" },
                "identity_workspace_missing",
            ),
            ("user_id", "identity_user_missing"),
        ],
        Subject::ServicePrincipal { .. } => &[("subject_id", "identity_principal_missing")],
    };
    for (key, reason) in fields {
        if value.get(key).is_none() {
            return Err(Error(reason));
        }
    }
    Ok(())
}
