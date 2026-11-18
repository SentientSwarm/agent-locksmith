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
    if let Err(response) = validate(state, name).await {
        return *response;
    }
    let lock = state.locks.get(name, label).await;
    let _guard = lock.lock().await;
    let session = match create(state, name, label, &body.refresh_token).await {
        Ok(s) => s,
        Err(response) => return *response,
    };
    let updated = match exchange(state, name, &session).await {
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

/// The registration must be an OAuth tool or model, and its route's egress
/// must allow the token call (AGENT-269); checked before any session row
/// is written. The exchange re-reads the serving registration.
async fn validate(state: &OauthAdminState, name: &str) -> Result<(), Box<Response>> {
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
    // AGENT-302: no admission or refresh path uses an infra session.
    if registration.kind == crate::registrations::Kind::Infra {
        return Err(Box::new(error_envelope(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "not_oauth_registration",
            "OAuth custody serves tool and model registrations only",
        )));
    }
    state
        .token_clients
        .for_egress(registration.egress)
        .map(|_| ())
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

/// AGENT-302: the token endpoint and the egress come from one serving
/// registration, so an edit racing the bootstrap cannot pair them. That
/// registration is checked again as `validate` checked the database row:
/// a serving catalog that still shows the name as infra (a failed catalog
/// refresh, or a change since `validate`) serves no session, and the
/// operator is told to start again, as a device login is.
async fn exchange(
    state: &OauthAdminState,
    name: &str,
    session: &OauthSession,
) -> Result<OauthSession, Box<Response>> {
    let cat = state.catalog.load();
    let serving = cat.lookup_active(name);
    if serving.is_some_and(|r| r.kind == crate::registrations::Kind::Infra) {
        let _ = state.sessions.delete_if_current(session).await;
        return Err(Box::new(error_envelope(
            StatusCode::CONFLICT,
            "conflict",
            "authority_changed",
            "the registration is not being served as an OAuth tool or model; start again",
        )));
    }
    let Some(registration) = serving else {
        let _ = state.sessions.delete_if_current(session).await;
        let e = crate::oauth::refresh::RefreshError::RegistrationGone(name.to_string());
        return Err(Box::new(error_envelope(
            StatusCode::BAD_GATEWAY,
            "auth_error",
            "oauth_bootstrap_failed",
            &format!("refresh exchange failed: {e}"),
        )));
    };
    let client = match state.token_clients.for_egress(registration.egress) {
        Ok(client) => client,
        Err(cause) => {
            let _ = state.sessions.delete_if_current(session).await;
            return Err(Box::new(egress_refused(cause)));
        }
    };
    let refreshed = crate::oauth::refresh::refresh_selected_session(
        &state.sessions,
        &registration.auth,
        &state.sealing_key,
        client,
        session,
    )
    .await;
    match refreshed {
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
