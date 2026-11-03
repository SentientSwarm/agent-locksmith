//! Exchange using the explicitly selected public OAuth metadata.
use super::*;

/// Token-endpoint response shape (RFC 6749 §5.1). `expires_in` is
/// optional per RFC but in practice all tested providers return it.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // we don't yet validate token_type — providers always say "Bearer"
    token_type: Option<String>,
}

pub async fn refresh_selected_session(
    repo: &OauthSessionRepository,
    selection: &AuthSpec,
    key: &SealingKey,
    client: &reqwest::Client,
    session: &OauthSession,
) -> Result<OauthSession, RefreshError> {
    let (token_url, client_id) = selected_parameters(selection)
        .ok_or_else(|| RefreshError::BadResponse("selected OAuth metadata is unusable".into()))?;

    use secrecy::ExposeSecret;
    if session.refresh_token.expose_secret().is_empty() {
        return Err(RefreshError::BadResponse("empty refresh token".into()));
    }
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", session.refresh_token.expose_secret()),
        ("client_id", client_id),
    ];

    let response = client
        .post(token_url)
        .form(&form)
        .send()
        .await
        .map_err(|_| RefreshError::Network("token endpoint unavailable".into()))?;

    let status = response.status();
    if !status.is_success() {
        // 4xx (especially 400 invalid_grant / 401 invalid_client) means
        // the refresh token is no longer valid. Operator-action recovery.
        if status.is_client_error() {
            return Err(RefreshError::Revoked {
                status: status.as_u16(),
            });
        }
        // 5xx is provider-side; same outcome (mark degraded) since we
        // don't auto-retry. Operator can re-bootstrap when provider
        // recovers.
        return Err(RefreshError::ProviderError {
            status: status.as_u16(),
        });
    }

    let token_response: TokenResponse = response
        .json()
        .await
        .map_err(|_| RefreshError::BadResponse("invalid token response".into()))?;

    if token_response.access_token.is_empty()
        || token_response
            .refresh_token
            .as_ref()
            .is_some_and(|t| t.is_empty())
    {
        return Err(RefreshError::BadResponse("empty token response".into()));
    }
    // expires_in is RFC-optional but in practice always present. If
    // missing, default to 1 hour — common provider default.
    let lifetime = token_response.expires_in.unwrap_or(3600);
    let new_expires_at = unix_now() + lifetime;

    repo.update_tokens(
        key,
        &session.name,
        &session.session_label,
        &token_response.access_token,
        new_expires_at,
        token_response.refresh_token.as_deref(),
    )
    .await
    .map_err(|e| RefreshError::Persist(e.to_string()))?;

    info!(
        name = %session.name,
        session_label = %session.session_label,
        oauth_session_id = %session.audit_session_id(),
        new_lifetime_secs = lifetime,
        "oauth refresh succeeded"
    );

    // Read back the canonical state.
    repo.get(key, &session.name, &session.session_label)
        .await
        .map_err(|e| RefreshError::Persist(e.to_string()))?
        .ok_or_else(|| RefreshError::Persist("session vanished after update".to_string()))
}
