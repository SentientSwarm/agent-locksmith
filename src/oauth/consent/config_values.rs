use super::{Error, Result};
pub(super) fn managed_kind(kind: &str) -> bool {
    matches!(
        kind,
        "custom_oauth_v1"
            | "controlled_linear_v1"
            | "linear_hosted_v1"
            | "linear_hosted_fixture_v1"
            | "slack_confidential_v1"
            | "slack_confidential_fixture_v1"
    )
}
pub(super) fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

pub(super) fn endpoint(raw: &str, path: &str) -> Result<reqwest::Url> {
    let url = https(raw, path)?;
    if !matches!(url.host_str(), Some("127.0.0.1" | "[::1]")) {
        return Err(Error("invalid_profile"));
    }
    Ok(url)
}
pub(super) fn https(raw: &str, path: &str) -> Result<reqwest::Url> {
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
