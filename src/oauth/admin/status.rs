use super::*;

/// `GET /admin/operator/oauth/<name>[?label=<label>]`.
pub async fn op_oauth_status(
    State(state): State<OauthAdminState>,
    Path(name): Path<String>,
    Query(label_q): Query<LabelQuery>,
) -> Response {
    let session_label = label_q.label_or_default();
    match state
        .sessions
        .get(&state.sealing_key, &name, session_label)
        .await
    {
        Ok(Some(session)) => status_response(&session),
        Ok(None) => (
            StatusCode::OK,
            Json(json!({
                "name": name,
                "session_label": session_label,
                "present": false,
            })),
        )
            .into_response(),
        Err(_) => error_envelope(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_error",
            "internal_error",
            "OAuth custody operation failed",
        ),
    }
}

/// `GET /admin/operator/oauth`. Lists all sessions across all
/// registrations + labels (Phase G, no path param). Operator-only.
pub async fn op_oauth_list(State(state): State<OauthAdminState>) -> Response {
    match state.sessions.list_all().await {
        Ok(rows) => {
            let arr: Vec<Value> = rows
                .into_iter()
                .map(
                    |(name, session_label, degraded, expires_at, refresh_pending)| {
                        json!({
                            "name": name,
                            "session_label": session_label,
                            "degraded": degraded,
                            "refresh_pending": refresh_pending,
                            "reconnect_required": refresh_pending || degraded,
                            "access_token_expires_at": expires_at,
                        })
                    },
                )
                .collect();
            (StatusCode::OK, Json(json!({ "sessions": arr }))).into_response()
        }
        Err(_) => error_envelope(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_error",
            "internal_error",
            "OAuth custody operation failed",
        ),
    }
}

/// `DELETE /admin/operator/oauth/<name>[?label=<label>]`. Returns
/// 204 on either success or absent (idempotent).
pub async fn op_oauth_revoke(
    State(state): State<OauthAdminState>,
    Path(name): Path<String>,
    Query(label_q): Query<LabelQuery>,
) -> Response {
    let session_label = label_q.label_or_default();
    match state.sessions.delete(&name, session_label).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => error_envelope(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_error",
            "internal_error",
            "OAuth custody operation failed",
        ),
    }
}

fn status_response(session: &OauthSession) -> Response {
    (StatusCode::OK, Json(session_status_json(session, true))).into_response()
}
