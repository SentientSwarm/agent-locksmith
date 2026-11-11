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
    pub consent: Option<Arc<crate::oauth::consent::Runtime>>,
    pub registrations: Arc<RegistrationRepository>,
    pub sessions: OauthSessionRepository,
    pub sealing_key: SealingKey,
    pub catalog: Arc<arc_swap::ArcSwap<Catalog>>,
    pub locks: RefreshLockMap,
    /// #138: pending operator device logins (in memory only).
    pub device_logins: DeviceLogins,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBody {
    /// Refresh token obtained out-of-band (provider's own CLI flow,
    /// browser dev tools, etc.). v1.0 limitation; v1.1+ replaces with
    /// interactive PKCE / device-code flows that obtain this directly.
    pub refresh_token: String,
}

mod bootstrap;
mod device_login;
mod status;
mod warnings;
pub use bootstrap::op_oauth_bootstrap;
pub use device_login::{DeviceLogins, op_oauth_device_login_poll, op_oauth_device_login_start};
pub use status::{op_oauth_list, op_oauth_revoke, op_oauth_status};

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
        "refresh_pending": session.refresh_pending,
        "reconnect_required": session.refresh_pending || session.degraded,
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
