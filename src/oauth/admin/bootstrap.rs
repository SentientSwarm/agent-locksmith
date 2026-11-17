use super::*;

/// Bootstrap and refresh share a network lock. Revoke intentionally does not.
pub async fn op_oauth_bootstrap(
    State(state): State<OauthAdminState>,
    Path(name): Path<String>,
    Query(label_q): Query<LabelQuery>,
    Json(body): Json<BootstrapBody>,
) -> Response {
    state
        .locks
        .owner
        .run(bootstrap(&state, &name, label_q.label_or_default(), &body))
        .await
        .unwrap_or_else(|| {
            error_envelope(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_error",
                "oauth_shutting_down",
                "OAuth operation stopped during daemon shutdown",
            )
        })
}

async fn bootstrap(
    state: &OauthAdminState,
    name: &str,
    label: &str,
    body: &BootstrapBody,
) -> Response {
    let client = match validate(state, name).await {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let lock = state.locks.get(name, label).await;
    let _guard = lock.lock().await;
    let session = match create(state, name, label, &body.refresh_token).await {
        Ok(s) => s,
        Err(response) => return *response,
    };
    let updated = match exchange(state, &client, &session).await {
        Ok(s) => s,
        Err(response) => return *response,
    };
    let warnings = super::warnings::collision_warnings(state, name, label).await;
    let mut body = session_status_json(&updated, true);
    if !warnings.is_empty() {
        body["warnings"] = json!(warnings);
    }
    (StatusCode::OK, Json(body)).into_response()
}

/// The registration must be OAuth, and its route's egress must allow the
/// token call (AGENT-269); checked before any session row is written.
async fn validate(state: &OauthAdminState, name: &str) -> Result<reqwest::Client, Box<Response>> {
    let registration = match state.registrations.get(name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(Box::new(error_envelope(
                StatusCode::NOT_FOUND,
                "not_found",
                "unknown_name",
                "registration not found",
            )));
        }
        Err(_) => {
            return Err(Box::new(error_envelope(
                StatusCode::INTERNAL_SERVER_ERROR,
                "auth_error",
                "internal_error",
                "registration read failed",
            )));
        }
    };
    validate_shape(&registration.auth)?;
    state
        .token_clients
        .for_egress(registration.egress)
        .cloned()
        .map_err(|cause| Box::new(egress_refused(cause)))
}

fn validate_shape(auth: &AuthSpec) -> Result<(), Box<Response>> {
    if !matches!(
        auth,
        AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. }
    ) {
        return Err(Box::new(error_envelope(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "not_oauth_registration",
            "registration is not an OAuth shape",
        )));
    }
    Ok(())
}

async fn create(
    state: &OauthAdminState,
    name: &str,
    label: &str,
    refresh: &str,
) -> Result<OauthSession, Box<Response>> {
    state
        .sessions
        .create(&state.sealing_key, name, label, refresh, None, None, "")
        .await
        .map_err(create_error)
}

pub(super) fn create_error(e: crate::oauth::session::OauthSessionError) -> Box<Response> {
    if matches!(e, crate::oauth::OauthSessionError::UnsupportedKind) {
        return Box::new(super::status::unsupported());
    }
    if e.to_string().contains("UNIQUE") || e.to_string().contains("constraint") {
        return Box::new(error_envelope(
            StatusCode::CONFLICT,
            "conflict",
            "session_exists",
            "session already bootstrapped; revoke before re-bootstrapping",
        ));
    }
    Box::new(error_envelope(
        StatusCode::INTERNAL_SERVER_ERROR,
        "auth_error",
        "internal_error",
        "OAuth custody operation failed",
    ))
}

async fn exchange(
    state: &OauthAdminState,
    client: &reqwest::Client,
    session: &OauthSession,
) -> Result<OauthSession, Box<Response>> {
    let cat = state.catalog.load();
    match refresh_session(&state.sessions, &cat, &state.sealing_key, client, session).await {
        Ok(updated) => Ok(updated),
        Err(e) => {
            // Only this attempt's unchanged, committed bootstrap row can be removed.
            let _ = state.sessions.delete_if_current(session).await;
            Err(Box::new(error_envelope(
                StatusCode::BAD_GATEWAY,
                "auth_error",
                "oauth_bootstrap_failed",
                &format!("refresh exchange failed: {e}"),
            )))
        }
    }
}
