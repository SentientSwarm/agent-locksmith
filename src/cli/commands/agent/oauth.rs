//! Snapshot OAuth metadata when the owner explicitly selects a session.
use crate::client::{Auth, CliClient, CliError};
use serde_json::Value;

pub(super) async fn selection(
    client: &CliClient,
    token: &str,
    name: &str,
    label: &str,
) -> Result<Value, CliError> {
    validate_label(label)?;
    for kind in ["models", "tools", "infra"] {
        let result = client
            .json::<Value>(
                "GET",
                &format!("/admin/operator/{kind}/{name}"),
                Auth::Operator(token),
                None,
            )
            .await;
        match result {
            Ok(row) => return with_label(row["auth"].clone(), label),
            Err(CliError::Server { status: 404, .. }) => continue,
            Err(CliError::Server { status: 409, body }) if wrong_kind(&body) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(CliError::Usage(
        "registration not found; register an OAuth provider before selecting its session".into(),
    ))
}

fn wrong_kind(body: &str) -> bool {
    serde_json::from_str::<Value>(body).is_ok_and(|value| value["error"]["code"] == "wrong_kind")
}

fn with_label(mut auth: Value, label: &str) -> Result<Value, CliError> {
    if !matches!(
        auth["kind"].as_str(),
        Some("oauth_pkce" | "oauth_device_code")
    ) {
        return Err(CliError::Usage(
            "registration is not OAuth; select the intended source explicitly".into(),
        ));
    }
    auth["session_label"] = Value::String(label.into());
    Ok(auth)
}

fn validate_label(label: &str) -> Result<(), CliError> {
    if label.is_empty()
        || !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CliError::Usage(
            "session label must be nonempty ASCII alphanumeric / '-' / '_'".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::wrong_kind;

    #[test]
    fn kind_lookup_continues_only_for_the_wrong_kind_envelope() {
        assert!(wrong_kind(r#"{"error":{"code":"wrong_kind"}}"#));
        for body in [
            r#"{"error":{"code":"name_in_use","message":"wrong_kind"}}"#,
            "wrong_kind",
            "{",
            r#"{"code":"wrong_kind"}"#,
        ] {
            assert!(!wrong_kind(body));
        }
    }
}
