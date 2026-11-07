//! Typed observed identity enters the existing custody transaction here.
use super::{
    super::{Error, Result, config::Profile},
    Subject,
};
use sqlx::{Row, sqlite::SqliteRow};

pub(in crate::oauth::consent) struct Facts<'a> {
    pub workspace: Option<&'a str>,
    pub user: Option<&'a str>,
    pub encoded: Option<String>,
    pub client_auth: &'static str,
}
fn client_auth(p: &Profile) -> &'static str {
    if p.confidential() {
        "client_secret_post"
    } else {
        "none"
    }
}
pub(in crate::oauth::consent) fn facts<'a>(
    p: &'a Profile,
    observed: Option<&'a Subject>,
) -> Result<Facts<'a>> {
    let client_auth = client_auth(p);
    if let Some(c) = &p.contract {
        let observed = observed
            .filter(|s| *s == &c.subject)
            .ok_or(Error("identity_mismatch"))?;
        let (workspace, user) = observed.workspace_user();
        return Ok(Facts {
            workspace,
            user,
            client_auth,
            encoded: Some(serde_json::to_string(observed).map_err(|_| Error("identity_mismatch"))?),
        });
    }
    if observed.is_some() {
        return Err(Error("identity_mismatch"));
    }
    Ok(Facts {
        workspace: Some(&p.expected_workspace),
        user: Some(&p.expected_user),
        encoded: None,
        client_auth,
    })
}
pub(in crate::oauth::consent) fn matches(row: &SqliteRow, p: &Profile) -> Result<bool> {
    if let Some(c) = &p.contract {
        let subject = stored(row)?;
        let (workspace, user) = subject.workspace_user();
        let observed_scope: &str = row.get("scope");
        // Custody stores validated evidence in declaration order, space-separated.
        // The provider's response separator applies only at the wire boundary.
        let scope_matches =
            row.get::<bool, _>("scope_echoed") && observed_scope == c.scope.required.join(" ");
        return Ok(scope_matches
            && subject == c.subject
            && row.get::<Option<&str>, _>("workspace_id") == workspace
            && row.get::<Option<&str>, _>("user_id") == user
            && row.get::<&str, _>("client_auth") == c.client_auth);
    }
    Ok(row.get::<Option<&str>, _>("subject_json").is_none()
        && row.get::<Option<&str>, _>("workspace_id") == Some(p.expected_workspace.as_str())
        && row.get::<Option<&str>, _>("user_id") == Some(p.expected_user.as_str()))
}
pub(in crate::oauth::consent) fn stored(row: &SqliteRow) -> Result<Subject> {
    let raw = row
        .get::<Option<&str>, _>("subject_json")
        .ok_or(Error("custody_failed"))?;
    serde_json::from_str(raw).map_err(|_| Error("custody_failed"))
}
