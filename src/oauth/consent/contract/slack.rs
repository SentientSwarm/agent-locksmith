use super::{
    super::{Error, Result, slack_metadata},
    Contract, Subject,
};
use serde_json::Value;

pub(super) fn check(c: &Contract, v: &Value) -> Result<String> {
    let Subject::UserWorkspace {
        workspace_id,
        user_id,
    } = &c.subject
    else {
        return Err(Error("invalid_profile"));
    };
    let scope = match v.get("authed_user") {
        Some(user) => nested(c, v, user, workspace_id, user_id)?,
        None => root(c, v)?,
    };
    if let Some(team) = v.get("team") {
        parent(team, "id", workspace_id)?;
    }
    if let Some(root) = v.get("scope")
        && c.scope.evidence(Some(root))? != scope
    {
        return Err(Error("token_metadata_mismatch"));
    }
    Ok(scope)
}
fn nested(
    c: &Contract,
    v: &Value,
    user: &Value,
    workspace: &str,
    expected_user: &str,
) -> Result<String> {
    if v.get("ok") != Some(&Value::Bool(true)) || v["token_type"] != "user" {
        return Err(Error("token_response_refused"));
    }
    parent(user, "id", expected_user)?;
    parent(
        v.get("team").ok_or(Error("token_metadata_mismatch"))?,
        "id",
        workspace,
    )?;
    slack_metadata::echoes(v)?;
    c.scope.evidence(user.get("scope"))
}
fn parent(v: &Value, key: &str, expected: &str) -> Result<()> {
    if !v.is_object() || v.get(key).and_then(Value::as_str) != Some(expected) {
        return Err(Error("token_metadata_mismatch"));
    }
    Ok(())
}

fn root(c: &Contract, v: &Value) -> Result<String> {
    let kind = v
        .get("token_type")
        .and_then(Value::as_str)
        .ok_or(Error("token_response_refused"))?;
    if kind != "user" && !kind.eq_ignore_ascii_case("Bearer") {
        return Err(Error("token_response_refused"));
    }
    c.scope.evidence(v.get("scope"))
}
