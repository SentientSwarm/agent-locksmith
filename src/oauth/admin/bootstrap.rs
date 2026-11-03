use super::*;

/// Bootstrap and refresh share a network lock. Revoke intentionally does not.
pub async fn op_oauth_bootstrap(
    State(state): State<OauthAdminState>,
    Path(name): Path<String>,
    Query(label_q): Query<LabelQuery>,
    Json(body): Json<BootstrapBody>,
) -> Response {
    let label = label_q.label_or_default();
    if let Err(response) = validate(&state, &name).await {
        return response;
    }
    let lock = state.locks.get(&name, label).await;
    let _guard = lock.lock().await;
    let session = match create(&state, &name, label, &body.refresh_token).await {
        Ok(s) => s,
        Err(response) => return response,
    };
    let updated = match exchange(&state, &session).await {
        Ok(s) => s,
        Err(response) => return response,
    };
    let warnings = super::warnings::collision_warnings(&state, &name, label).await;
    let mut body = session_status_json(&updated, true);
    if !warnings.is_empty() {
        body["warnings"] = json!(warnings);
    }
    (StatusCode::OK, Json(body)).into_response()
}

async fn validate(state: &OauthAdminState, name: &str) -> Result<(), Response> {
    let registration = match state.registrations.get(name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(error_envelope(
                StatusCode::NOT_FOUND,
                "not_found",
                "unknown_name",
                "registration not found",
            ));
        }
        Err(_) => {
            return Err(error_envelope(
                StatusCode::INTERNAL_SERVER_ERROR,
                "auth_error",
                "internal_error",
                "registration read failed",
            ));
        }
    };
    validate_shape(&registration.auth)
}

// Cold path returns the finished HTTP response; avoid boxing solely for size.
#[allow(clippy::result_large_err)]
fn validate_shape(auth: &AuthSpec) -> Result<(), Response> {
    if !matches!(
        auth,
        AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. }
    ) {
        return Err(error_envelope(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "not_oauth_registration",
            "registration is not an OAuth shape",
        ));
    }
    Ok(())
}

async fn create(
    state: &OauthAdminState,
    name: &str,
    label: &str,
    refresh: &str,
) -> Result<OauthSession, Response> {
    state
        .sessions
        .create(&state.sealing_key, name, label, refresh, None, None, "")
        .await
        .map_err(create_error)
}

fn create_error(e: crate::oauth::session::OauthSessionError) -> Response {
    if e.to_string().contains("UNIQUE") || e.to_string().contains("constraint") {
        return error_envelope(
            StatusCode::CONFLICT,
            "conflict",
            "session_exists",
            "session already bootstrapped; revoke before re-bootstrapping",
        );
    }
    error_envelope(
        StatusCode::INTERNAL_SERVER_ERROR,
        "auth_error",
        "internal_error",
        "OAuth custody operation failed",
    )
}

async fn exchange(
    state: &OauthAdminState,
    session: &OauthSession,
) -> Result<OauthSession, Response> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let cat = state.catalog.load();
    match refresh_session(&state.sessions, &cat, &state.sealing_key, &client, session).await {
        Ok(updated) => Ok(updated),
        Err(e) => {
            // Only this attempt's unchanged, committed bootstrap row can be removed.
            let _ = state.sessions.delete_if_current(session).await;
            Err(error_envelope(
                StatusCode::BAD_GATEWAY,
                "auth_error",
                "oauth_bootstrap_failed",
                &format!("refresh exchange failed: {e}"),
            ))
        }
    }
}
