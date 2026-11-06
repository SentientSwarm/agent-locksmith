use super::*;

pub(crate) async fn selected_source(
    bindings: &crate::repo::AgentCredentialRepository,
    name: &str,
    session_label: &str,
) -> Result<Option<AuthSpec>, ()> {
    let rows = bindings.list_all().await.map_err(|_| ())?;
    consensus(
        rows.iter()
            .filter(|row| {
                row.registration == name
                    && row.auth_spec.oauth_session_label() == Some(session_label)
                    && !session_label.trim().is_empty()
            })
            .map(|row| &row.auth_spec),
    )
}

/// Shared-session metadata rule, also used inside the offline migration transaction.
pub(crate) fn consensus<'a>(
    specs: impl Iterator<Item = &'a AuthSpec>,
) -> Result<Option<AuthSpec>, ()> {
    let mut selected = None;
    for spec in specs {
        if selected_parameters(spec).is_none()
            || selected.as_ref().is_some_and(|prior| prior != spec)
        {
            return Err(());
        }
        selected = Some(spec.clone());
    }
    Ok(selected)
}

/// Public OAuth metadata must be usable before a selected session is read.
pub fn selected_parameters(spec: &AuthSpec) -> Option<(&str, &str)> {
    let (url, client) = match spec {
        AuthSpec::OauthPkce {
            token_url,
            client_id,
            ..
        }
        | AuthSpec::OauthDeviceCode {
            token_url,
            client_id,
            ..
        } => (token_url, client_id),
        _ => return None,
    };
    let parsed = reqwest::Url::parse(url).ok()?;
    if client.trim().is_empty()
        || !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
    {
        return None;
    }
    Some((url.as_str(), client.as_str()))
}
