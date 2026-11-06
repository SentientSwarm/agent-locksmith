//! Atomic per-agent stored-value ingestion with explicit bearer intent.
use super::{
    service::AdminError,
    uds::{UdsState, admin_err_response},
};
use crate::{
    auth_v2::OperatorIdentity,
    registrations::AuthSpec,
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
        Ok(value) => {
            state.resync_op_references().await;
            Json(value).into_response()
        }
        Err(error) => admin_err_response(error),
    }
}
fn failure(code: &str, status: StatusCode) -> Response {
    (status, Json(json!({"error":{"code":code}}))).into_response()
}
fn invalid(body: &Input) -> bool {
    body.bearer && body.header.is_some()
        || body.value.expose_secret().len() > 8192
        || (body.bearer
            && (body.value.expose_secret().is_empty()
                || !body
                    .value
                    .expose_secret()
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b))))
}
async fn write(
    state: &UdsState,
    op: &OperatorIdentity,
    id: &str,
    registration: &str,
    body: Input,
) -> Result<serde_json::Value, AdminError> {
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
    let (header, old_ref) = shape(&mut tx, agent.id, registration, &body).await?;
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
    Ok(
        json!({"agent_public_id":agent.public_id,"registration":registration,"secret_ref":secret_ref}),
    )
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
) -> Result<(Option<String>, Option<String>), AdminError> {
    let row = sqlx::query("SELECT r.auth_json,b.auth_spec AS selected FROM registrations r LEFT JOIN agent_credential_overrides b ON b.registration=r.name AND b.agent_id=? WHERE r.name=? AND r.disabled=0 AND r.kind IN ('tool','model')")
        .bind(agent).bind(name).fetch_optional(c).await.map_err(|_| unavailable())?.ok_or(AdminError::InvalidGrantTarget)?;
    let selected: Option<String> = row.get("selected");
    let selected: Option<AuthSpec> = selected
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .map_err(|_| unavailable())?;
    let old = selected
        .as_ref()
        .and_then(AuthSpec::stored_secret_ref)
        .map(str::to_owned);
    let default: AuthSpec =
        serde_json::from_str(&row.get::<String, _>("auth_json")).map_err(|_| unavailable())?;
    Ok((header(body, selected.as_ref().unwrap_or(&default)), old))
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
