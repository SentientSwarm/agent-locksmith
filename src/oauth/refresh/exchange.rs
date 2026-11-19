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
        if crate::oauth::is_followable_redirect(status) {
            return Err(RefreshError::Redirected {
                status: status.as_u16(),
            });
        }
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

#[cfg(test)]
mod redirect_tests {
    use super::*;

    fn answer(status: u16) -> reqwest::Response {
        axum::http::Response::builder()
            .status(status)
            .header("location", "https://elsewhere.example/oauth/token")
            .body("")
            .unwrap()
            .into()
    }

    /// AGENT-302: token calls do not follow redirects, so a 3xx from the
    /// token endpoint fails the refresh. It must say so, not report a 5xx.
    #[tokio::test]
    async fn a_redirected_token_call_is_reported_as_a_redirect() {
        for status in [301, 302, 307, 308] {
            let Err(error) = parse_tokens(answer(status)).await else {
                panic!("{status} must fail the refresh");
            };
            assert_eq!(error.audit_cause(), "token_redirect", "{status}");
            let text = error.to_string();
            assert!(text.contains(&status.to_string()), "{text}");
            assert!(text.contains("token_url"), "{text}");
            assert!(
                !text.contains("elsewhere"),
                "location must not be quoted: {text}"
            );
        }
    }

    /// AGENT-328: 300 and 304 are 3xx but not redirects a client would
    /// follow, so they must not tell the operator to change token_url.
    #[tokio::test]
    async fn multiple_choices_and_not_modified_are_not_redirects() {
        for status in [300, 304] {
            let Err(error) = parse_tokens(answer(status)).await else {
                panic!("{status} must fail the refresh");
            };
            assert_ne!(error.audit_cause(), "token_redirect", "{status}");
            assert!(!error.to_string().contains("token_url"), "{status}");
        }
    }

    #[tokio::test]
    async fn a_server_error_is_still_reported_as_one() {
        let Err(error) = parse_tokens(answer(503)).await else {
            panic!("503 must fail the refresh");
        };
        assert_eq!(error.audit_cause(), "provider_5xx");
    }
}
