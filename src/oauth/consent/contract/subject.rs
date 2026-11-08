use super::super::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Subject {
    UserWorkspace {
        workspace_id: String,
        user_id: String,
    },
    ServicePrincipal {
        subject_id: String,
    },
}
impl Subject {
    pub(super) fn valid(&self) -> bool {
        match self {
            Self::UserWorkspace {
                workspace_id,
                user_id,
            } => valid(workspace_id) && valid(user_id),
            Self::ServicePrincipal { subject_id } => valid(subject_id),
        }
    }
    pub(super) fn observe(&self, value: &Value, slack: bool) -> Result<Self> {
        let actual = match self {
            Self::UserWorkspace { .. } => Self::UserWorkspace {
                workspace_id: text(value, if slack { "team_id" } else { "workspace_id" })?,
                user_id: text(value, "user_id")?,
            },
            Self::ServicePrincipal { .. } => Self::ServicePrincipal {
                subject_id: text(value, "subject_id")?,
            },
        };
        if &actual != self {
            return Err(Error("identity_mismatch"));
        }
        Ok(actual)
    }
    pub(super) fn echoes(&self, value: &Value) -> Result<()> {
        self.parent_echoes(value)?;
        let fields: Vec<(&str, &str)> = match self {
            Self::UserWorkspace {
                workspace_id,
                user_id,
            } => vec![
                ("workspace_id", workspace_id),
                ("team_id", workspace_id),
                ("user_id", user_id),
            ],
            Self::ServicePrincipal { subject_id } => vec![("subject_id", subject_id)],
        };
        for (key, expected) in fields {
            if value.get(key).is_some() && text(value, key)? != expected {
                return Err(Error("identity_mismatch"));
            }
        }
        let forbidden: &[&str] = match self {
            Self::UserWorkspace { .. } => &["subject_id", "bot_id", "bot_user_id"],
            Self::ServicePrincipal { .. } => {
                &["user_id", "workspace_id", "team_id", "authed_user", "team"]
            }
        };
        if forbidden.iter().any(|k| value.get(k).is_some()) {
            return Err(Error("identity_mismatch"));
        }
        Ok(())
    }
    fn parent_echoes(&self, value: &Value) -> Result<()> {
        if let Self::UserWorkspace {
            workspace_id,
            user_id,
        } = self
        {
            for (key, expected) in [("team", workspace_id), ("authed_user", user_id)] {
                if let Some(parent) = value.get(key)
                    && (!parent.is_object() || text(parent, "id")? != *expected)
                {
                    return Err(Error("identity_mismatch"));
                }
            }
            if value.get("is_bot").is_some_and(|v| v != false) {
                return Err(Error("identity_mismatch"));
            }
        }
        Ok(())
    }
    pub(crate) fn workspace_user(&self) -> (Option<&str>, Option<&str>) {
        match self {
            Self::UserWorkspace {
                workspace_id,
                user_id,
            } => (Some(workspace_id), Some(user_id)),
            Self::ServicePrincipal { .. } => (None, None),
        }
    }
}
fn valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn text(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| valid(s))
        .map(str::to_owned)
        .ok_or(Error("identity_mismatch"))
}
