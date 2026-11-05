//! Exchange using the explicitly selected public OAuth metadata.
use super::*;
use secrecy::ExposeSecret;

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
    if session.refresh_pending || session.degraded {
        return Err(RefreshError::ReconnectRequired);
    }
    selected_parameters(selection)
        .ok_or_else(|| RefreshError::BadResponse("selected OAuth metadata is unusable".into()))?;
    if session.refresh_token.expose_secret().is_empty() {
        return Err(RefreshError::BadResponse("empty refresh token".into()));
    }
    let attempt = repo
        .begin_refresh(key, session)
        .await
        .map_err(|_| RefreshError::Persist("OAuth refresh claim failed".into()))?;
    #[cfg(test)]
    super::recovery_barrier::reach("claimed").await;
    let token_response = request_tokens(selection, client, session).await?;
    complete(repo, key, &attempt, token_response).await
}

async fn complete(
    repo: &OauthSessionRepository,
    key: &SealingKey,
    attempt: &crate::oauth::session::RefreshAttempt,
    token_response: TokenResponse,
) -> Result<OauthSession, RefreshError> {
    let session = attempt.session();
    let lifetime = token_response.expires_in.unwrap_or(3600);
    let committed = repo
        .complete_refresh(
            key,
            attempt,
            &token_response.access_token,
            unix_now() + lifetime,
            token_response.refresh_token.as_deref(),
        )
        .await
        .map_err(|_| RefreshError::Persist("session changed or custody write failed".into()))?;
    info!(name = %session.name, session_label = %session.session_label,
        oauth_session_id = %session.audit_session_id(), new_lifetime_secs = lifetime,
        "oauth refresh succeeded");
    Ok(committed)
}

async fn request_tokens(
    selection: &AuthSpec,
    client: &reqwest::Client,
    session: &OauthSession,
) -> Result<TokenResponse, RefreshError> {
    let (token_url, client_id) = selected_parameters(selection)
        .ok_or_else(|| RefreshError::BadResponse("selected OAuth metadata is unusable".into()))?;

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

    parse_tokens(response).await
}

async fn parse_tokens(response: reqwest::Response) -> Result<TokenResponse, RefreshError> {
    let status = response.status();
    if !status.is_success() {
        if status.is_client_error() {
            return Err(RefreshError::Revoked {
                status: status.as_u16(),
            });
        }
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
    Ok(token_response)
}
