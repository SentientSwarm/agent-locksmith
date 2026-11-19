//! Atomic per-agent stored-value ingestion with explicit bearer intent.
use super::{
    service::AdminError,
    uds::{UdsState, admin_err_response},
};
use crate::{
    auth_v2::OperatorIdentity,
    registrations::{AuthSpec, validators::valid_credential_value},
    repo::{AgentCredentialRepository, CredentialSecretsRepository},
};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use secrecy::ExposeSecret;
use serde_json::json;
use sqlx::Row;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    value: secrecy::SecretString,
    #[serde(default)]
    header: Option<String>,
    #[serde(default)]
    bearer: bool,
    /// Bind a stored header: `header`, else the route's own header name,
    /// never the agent's current binding; refused when neither names one
    /// (AGENT-325). Without it, an absent `header` inherits the current
    /// binding's header and falls back to a stored bearer.
    #[serde(default)]
    stored_header: bool,
}
pub(super) async fn set(
    state: UdsState,
    op: OperatorIdentity,
    id: String,
    registration: String,
    body: Input,
) -> Response {
    if invalid(&body) {
        return failure("invalid_stored_credential", StatusCode::BAD_REQUEST);
    }
    if state.credential_sealing_key.is_none() || state.credential_secrets.is_none() {
        return failure("credential_store_unconfigured", StatusCode::NOT_FOUND);
    }
    match write(&state, &op, &id, &registration, body).await {
        Ok((value, written)) => {
            state
                .admin
                .audit_binding(
                    &op,
                    "agent_credential_set",
                    super::authority_audit::BindingChange {
                        agent_public_id: &written.agent_public_id,
                        registration: &registration,
                        binding: Some(&written.binding),
                        previous: written.previous.as_ref(),
                        error: None,
                    },
                )
                .await;
            state.resync_op_references().await;
            Json(value).into_response()
        }
        Err(Refused::Admin(error)) => admin_err_response(error),
        Err(Refused::Unnamed | Refused::Invalid) => {
            failure("invalid_stored_credential", StatusCode::BAD_REQUEST)
        }
    }
}
fn failure(code: &str, status: StatusCode) -> Response {
    (status, Json(json!({"error":{"code":code}}))).into_response()
}
fn invalid(body: &Input) -> bool {
    body.bearer && (body.header.is_some() || body.stored_header)
        || body
            .header
            .as_deref()
            .is_some_and(|h| crate::registrations::broker::validate_credential_header(h).is_err())
        || !valid_credential_value(body.value.expose_secret(), body.bearer)
}
/// Why a write changed nothing.
enum Refused {
    Admin(AdminError),
    /// `stored_header` with no `header` on a route that names none.
    Unnamed,
    /// A value that would be a stored bearer but can't be sent as one.
    Invalid,
}
impl From<AdminError> for Refused {
    fn from(e: AdminError) -> Self {
        Self::Admin(e)
    }
}
impl From<crate::repo::RepoError> for Refused {
    fn from(e: crate::repo::RepoError) -> Self {
        Self::Admin(e.into())
    }
}
/// What a successful write bound, for the audit row (AGENT-253).
struct Written {
    agent_public_id: String,
    binding: AuthSpec,
    previous: Option<AuthSpec>,
}
async fn write(
    state: &UdsState,
    op: &OperatorIdentity,
    id: &str,
    registration: &str,
    body: Input,
) -> Result<(serde_json::Value, Written), Refused> {
    let agent = state.admin.get_agent(op, id).await?;
    let creds = state.agent_creds.as_ref().ok_or_else(unavailable)?;
    let key = state
        .credential_sealing_key
        .as_ref()
        .ok_or_else(unavailable)?;
    let mut tx = creds
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| unavailable())?;
    let (header, previous) = shape(&mut tx, agent.id, registration, &body).await?;
    if body.stored_header && header.is_none() {
        return Err(Refused::Unnamed);
    }
    // AGENT-328: a value that falls back to a stored bearer is held to the
    // bearer rule, as if the caller had asked for one.
    if header.is_none() && !valid_credential_value(body.value.expose_secret(), true) {
        return Err(Refused::Invalid);
    }
    let old_ref = previous
        .as_ref()
        .and_then(AuthSpec::stored_secret_ref)
        .map(str::to_owned);
    let (sealed, nonce) = key
        .seal(body.value.expose_secret().as_bytes())
        .map_err(|_| unavailable())?;
    let secret_ref = CredentialSecretsRepository::insert_into(&mut tx, &sealed, &nonce).await?;
    let auth = auth(header, &secret_ref);
    AgentCredentialRepository::set_into(&mut tx, agent.id, registration, &auth).await?;
    tx.commit().await.map_err(|_| unavailable())?;
    if let (Some(old), Some(secrets)) = (old_ref, state.credential_secrets.as_ref()) {
        let _ = secrets.tombstone_if_unreferenced(&old).await;
    }
    let value = json!({"agent_public_id":agent.public_id,"registration":registration,"secret_ref":secret_ref});
    Ok((
        value,
        Written {
            agent_public_id: agent.public_id,
            binding: auth,
            previous,
        },
    ))
}
fn auth(header: Option<String>, secret_ref: &str) -> AuthSpec {
    match header {
        Some(header) => AuthSpec::StoredHeader {
            header,
            secret_ref: secret_ref.to_owned(),
        },
        None => AuthSpec::StoredBearer {
            secret_ref: secret_ref.to_owned(),
        },
    }
}
async fn shape(
    c: &mut sqlx::SqliteConnection,
    agent: i64,
    name: &str,
    body: &Input,
) -> Result<(Option<String>, Option<AuthSpec>), AdminError> {
    let row = sqlx::query("SELECT r.auth_json,b.auth_spec AS selected FROM registrations r LEFT JOIN agent_credential_overrides b ON b.registration=r.name AND b.agent_id=? WHERE r.name=? AND r.disabled=0 AND r.kind IN ('tool','model')")
        .bind(agent).bind(name).fetch_optional(c).await.map_err(|_| unavailable())?.ok_or(AdminError::InvalidGrantTarget)?;
    let selected: Option<String> = row.get("selected");
    let selected: Option<AuthSpec> = selected
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|_| unavailable())?;
    let default: AuthSpec =
        serde_json::from_str(&row.get::<String, _>("auth_json")).map_err(|_| unavailable())?;
    let inherited = if body.stored_header {
        &default
    } else {
        selected.as_ref().unwrap_or(&default)
    };
    Ok((header(body, inherited), selected))
}
fn header(body: &Input, inherited: &AuthSpec) -> Option<String> {
    if body.bearer {
        None
    } else {
        body.header
            .clone()
            .or_else(|| inherited.header_name().map(str::to_owned))
    }
}
fn unavailable() -> AdminError {
    AdminError::Backend("stored credential unavailable".into())
}
