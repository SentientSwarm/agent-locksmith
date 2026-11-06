//! Static diagnostic vocabulary only: no provider text enters an Error.
use super::{Error, Result, config::Profile};
use serde_json::Value;

struct Field([&'static str; 4]);
macro_rules! field {
    ($name:literal) => {
        Field([
            concat!("slack_token_", $name, "_missing"),
            concat!("slack_token_", $name, "_null"),
            concat!("slack_token_", $name, "_type"),
            concat!("slack_token_", $name, "_mismatch"),
        ])
    };
}

impl Field {
    fn shape<'a>(&self, v: Option<&'a Value>, valid: fn(&Value) -> bool) -> Result<&'a Value> {
        match v {
            None => Err(Error(self.0[0])),
            Some(v) if v.is_null() => Err(Error(self.0[1])),
            Some(v) if !valid(v) => Err(Error(self.0[2])),
            Some(v) => Ok(v),
        }
    }

    fn text(&self, v: Option<&Value>, expected: &str) -> Result<()> {
        if self.shape(v, Value::is_string)? != expected {
            return Err(Error(self.0[3]));
        }
        Ok(())
    }

    fn scopes(&self, v: Option<&Value>) -> Result<()> {
        let s = self.shape(v, Value::is_string)?.as_str().unwrap();
        let fields = s.split(',').collect::<Vec<_>>();
        if fields.len() != 2 || !super::slack::SCOPES.iter().all(|s| fields.contains(s)) {
            return Err(Error(self.0[3]));
        }
        Ok(())
    }
}

pub(super) fn check(p: &Profile, v: &Value) -> Result<()> {
    for (key, expected, field) in [
        ("issuer", &p.issuer, field!("issuer")),
        ("iss", &p.issuer, field!("iss")),
        ("resource", &p.resource, field!("resource")),
        ("client_id", &p.client_id, field!("client_id")),
    ] {
        if let Some(value) = v.get(key) {
            field.text(Some(value), expected)?;
        }
    }
    let team = field!("team").shape(v.get("team"), Value::is_object)?;
    field!("team_id").text(team.get("id"), &p.expected_workspace)?;
    let user = field!("authed_user").shape(v.get("authed_user"), Value::is_object)?;
    field!("authed_user_id").text(user.get("id"), &p.expected_user)?;
    field!("authed_user_scope").scopes(user.get("scope"))?;
    if let Some(value) = v.get("scope") {
        field!("root_scope").scopes(Some(value))?;
    }
    root_identity(p, v)
}

fn root_identity(p: &Profile, v: &Value) -> Result<()> {
    for (key, expected, field) in [
        ("team_id", &p.expected_workspace, field!("root_team_id")),
        ("user_id", &p.expected_user, field!("root_user_id")),
    ] {
        if let Some(value) = v.get(key) {
            field.text(Some(value), expected)?;
        }
    }
    Ok(())
}

macro_rules! nested {
    ($name:literal) => {
        [
            concat!("slack_token_nested_", $name, "_null"),
            concat!("slack_token_nested_", $name, "_type"),
            concat!("slack_token_nested_", $name, "_conflict"),
        ]
    };
}

pub(super) fn echoes(v: &Value) -> Result<()> {
    for (key, codes) in [
        ("access_token", nested!("access_token")),
        ("refresh_token", nested!("refresh_token")),
        ("expires_in", nested!("expires_in")),
        ("token_type", nested!("token_type")),
    ] {
        if let Some(nested) = v["authed_user"].get(key)
            && Some(nested) != v.get(key)
        {
            let typed = if key == "expires_in" {
                nested.is_u64()
            } else {
                nested.is_string()
            };
            return Err(Error(
                codes[if nested.is_null() {
                    0
                } else if !typed {
                    1
                } else {
                    2
                }],
            ));
        }
    }
    Ok(())
}
