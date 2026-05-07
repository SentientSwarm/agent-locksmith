//! Admin HTTP handlers for OAuth session management. Phase F.4.
//!
//! Three endpoints under `/admin/operator/oauth/<name>`:
//!
//! - `POST /bootstrap` — supply a refresh_token; daemon does the
//!   initial token-endpoint exchange to obtain the first access token,
//!   seals both, persists. v1.0 ships only the manual path (operator
//!   completes the OAuth dance with the provider's own CLI tool, then
//!   extracts the refresh token); v1.1+ adds interactive PKCE +
//!   device-code flows.
//! - `GET ` — session status (active / degraded / absent +
//!   expires_at + scope). Never leaks token cleartext.
//! - `DELETE ` — revoke locally; provider-side revocation deferred.
//!
//! All three are operator-credentialed. Routed under the existing
//! operator middleware; no agent-facing surface here.

use crate::oauth::refresh::{RefreshLockMap, refresh_session};
use crate::oauth::sealing::SealingKey;
use crate::oauth::session::{DEFAULT_SESSION_LABEL, OauthSession, OauthSessionRepository};
use crate::registrations::{AuthSpec, Catalog, RegistrationRepository};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// Common `?label=<label>` query string used by every OAuth admin
/// handler. Defaults to `DEFAULT_SESSION_LABEL` when absent so
/// pre-Phase-G clients (no `--label` arg) keep working unchanged.
#[derive(Debug, Deserialize, Default)]
pub struct LabelQuery {
    pub label: Option<String>,
}

impl LabelQuery {
    fn label_or_default(&self) -> &str {
        self.label.as_deref().unwrap_or(DEFAULT_SESSION_LABEL)
    }
}

/// State threaded into the OAuth admin handlers. Cheap clone — all
/// fields are `Arc` or owned-but-cheap.
#[derive(Clone)]
pub struct OauthAdminState {
    pub registrations: Arc<RegistrationRepository>,
    pub sessions: OauthSessionRepository,
    pub sealing_key: SealingKey,
    pub catalog: Arc<arc_swap::ArcSwap<Catalog>>,
    pub locks: RefreshLockMap,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBody {
    /// Refresh token obtained out-of-band (provider's own CLI flow,
    /// browser dev tools, etc.). v1.0 limitation; v1.1+ replaces with
    /// interactive PKCE / device-code flows that obtain this directly.
    pub refresh_token: String,
}

/// `POST /admin/operator/oauth/<name>/bootstrap[?label=<label>]`.
/// Body: `BootstrapBody`.
pub async fn op_oauth_bootstrap(
    State(state): State<OauthAdminState>,
    Path(name): Path<String>,
    Query(label_q): Query<LabelQuery>,
    Json(body): Json<BootstrapBody>,
) -> Response {
    let session_label = label_q.label_or_default();
    // Confirm the name is a registered OAuth shape.
    let registration = match state.registrations.get(&name).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return error_envelope(
                StatusCode::NOT_FOUND,
                "not_found",
                "unknown_name",
                "registration not found",
            );
        }
        Err(e) => {
            return error_envelope(
                StatusCode::INTERNAL_SERVER_ERROR,
                "auth_error",
                "internal_error",
                &format!("registrations: {e}"),
            );
        }
    };
    if !matches!(
        &registration.auth,
        AuthSpec::OauthPkce { .. } | AuthSpec::OauthDeviceCode { .. }
    ) {
        return error_envelope(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "not_oauth_registration",
            "registration is not an OAuth shape",
        );
    }

    // Hold the per-session lock from session-create through first
    // refresh so a racing background-refresh task can't observe a
    // half-bootstrapped row. Phase G: lock keys on
    // (registration name, session_label).
    let lock = state.locks.get(&name, session_label).await;
    let _guard = lock.lock().await;

    // Create session row with refresh_token sealed; access token
    // initially absent — populated by the inline refresh below.
    let session = match state
        .sessions
        .create(
            &state.sealing_key,
            &name,
            session_label,
            &body.refresh_token,
            None,
            None,
            "",
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            // INSERT may fail with PRIMARY KEY conflict if the
            // operator re-runs bootstrap on an existing session. Map
            // to 409 so the operator gets a clear path
            // (revoke first, then bootstrap, or wait for v1.1's
            // upsert semantics).
            if e.to_string().contains("UNIQUE") || e.to_string().contains("constraint") {
                return error_envelope(
                    StatusCode::CONFLICT,
                    "conflict",
                    "session_exists",
                    "session already bootstrapped; revoke before re-bootstrapping",
                );
            }
            return error_envelope(
                StatusCode::INTERNAL_SERVER_ERROR,
                "auth_error",
                "internal_error",
                &format!("oauth_sessions: {e}"),
            );
        }
    };

    // Inline refresh to obtain the first access token. Reuses the
    // background refresh path for consistency.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let cat = state.catalog.load();
    let updated =
        match refresh_session(&state.sessions, &cat, &state.sealing_key, &client, &session).await {
            Ok(updated) => updated,
            Err(e) => {
                // Bootstrap exchange failed — e.g., refresh token is
                // already expired, provider rejected our client_id, or
                // network failure. Roll back the half-bootstrapped row
                // so the operator can fix and retry without a 409.
                let _ = state.sessions.delete(&name, session_label).await;
                return error_envelope(
                    StatusCode::BAD_GATEWAY,
                    "auth_error",
                    "oauth_bootstrap_failed",
                    &format!("refresh exchange failed: {e}"),
                );
            }
        };

    // Phase G.4 — single-grant collision warning. When a non-default
    // label is bootstrapped and other labels already exist under the
    // same registration, the operator may be falling into the OAuth
    // single-grant trap (one ChatGPT account, two labels →
    // re-authenticating invalidates the prior label's refresh token
    // upstream). Soft-warn here so the trap is visible at bootstrap
    // time rather than 30 minutes later when the prior session's
    // background refresh fails.
    let warnings = collision_warnings(&state, &name, session_label).await;
    let mut body = session_status_json(&updated, /*present=*/ true);
    if !warnings.is_empty() {
        body["warnings"] = json!(warnings);
    }
    (StatusCode::OK, Json(body)).into_response()
}

/// Returns operator-visible warnings about other labels under the
/// same registration that may have been invalidated upstream.
async fn collision_warnings(
    state: &OauthAdminState,
    name: &str,
    bootstrapped_label: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rows) = state.sessions.list_all().await else {
        return out;
    };
    let other_labels: Vec<String> = rows
        .into_iter()
        .filter(|(n, l, _, _)| n == name && l != bootstrapped_label)
        .map(|(_, l, _, _)| l)
        .collect();
    if !other_labels.is_empty() {
        out.push(format!(
            "Registration `{name}` already has session label(s): {labels}. \
             If those sessions point at the same upstream account as \
             label `{bootstrapped_label}`, the provider has likely \
             invalidated the prior refresh tokens (single-grant OAuth \
             policy on OpenAI ChatGPT, GitHub, Google, etc.). \
             Per-agent OAuth requires distinct upstream accounts; see \
             concepts/per-agent-credentials.md.",
            labels = other_labels.join(", "),
        ));
    }
    out
}

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
        Ok(Some(session)) => {
            (StatusCode::OK, Json(session_status_json(&session, true))).into_response()
        }
        Ok(None) => (
            StatusCode::OK,
            Json(json!({
                "name": name,
                "session_label": session_label,
                "present": false,
            })),
        )
            .into_response(),
        Err(e) => error_envelope(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_error",
            "internal_error",
            &format!("oauth_sessions: {e}"),
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
                .map(|(name, session_label, degraded, expires_at)| {
                    json!({
                        "name": name,
                        "session_label": session_label,
                        "degraded": degraded,
                        "access_token_expires_at": expires_at,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "sessions": arr }))).into_response()
        }
        Err(e) => error_envelope(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_error",
            "internal_error",
            &format!("oauth_sessions: {e}"),
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
        Err(e) => error_envelope(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth_error",
            "internal_error",
            &format!("oauth_sessions: {e}"),
        ),
    }
}

/// Serialize an `OauthSession` for the operator status surface. Never
/// leaks token cleartext; `present` flag distinguishes "session exists"
/// from "registration exists but no session yet."
fn session_status_json(session: &OauthSession, present: bool) -> Value {
    json!({
        "name": session.name,
        "session_label": session.session_label,
        "present": present,
        "scope": session.scope,
        "degraded": session.degraded,
        "access_token_expires_at": session.access_token_expires_at,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
        "audit_session_id": session.audit_session_id(),
    })
}

fn error_envelope(status: StatusCode, ty: &str, code: &str, message: &str) -> Response {
    let body = json!({
        "error": {
            "type": ty,
            "code": code,
            "message": message,
        }
    });
    (status, Json(body)).into_response()
}
