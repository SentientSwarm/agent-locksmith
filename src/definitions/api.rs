//! Existing authenticated operator router; static errors never echo input.
use super::{Definition, Error, MAX_BYTES};
use crate::registrations::api::AdminRegistrationsState;
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};

pub fn router() -> Router<AdminRegistrationsState> {
    Router::new()
        .route(
            "/integration-definitions/{id}/revisions/{revision}",
            get(read).put(import),
        )
        .route(
            "/tools/{name}/from-definition",
            post(super::instance::create),
        )
}
async fn import(
    State(state): State<AdminRegistrationsState>,
    Path((id, revision)): Path<(String, String)>,
    request: Request,
) -> Result<Response, Error> {
    let definition = super::parse(&body(request).await?)?;
    if definition.id != id || definition.revision.to_string() != revision {
        return Err(Error::Invalid);
    }
    let created = state.repo.import_definition(&definition).await?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(document(&definition)?),
    )
        .into_response())
}
async fn read(
    State(state): State<AdminRegistrationsState>,
    Path((id, revision)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    let revision = revision.parse().map_err(|_| Error::Invalid)?;
    Ok(Json(document(
        &state.repo.get_definition(&id, revision).await?,
    )?))
}
fn document(d: &Definition) -> Result<Value, Error> {
    Ok(
        json!({"definition": d, "digest": d.digest()?, "authoring_only": true, "verification_source": "operator_declared", "provider_readiness": "unverified"}),
    )
}
pub(super) async fn body(request: Request) -> Result<Vec<u8>, Error> {
    if request
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(';').next().unwrap_or("").trim())
        != Some("application/json")
    {
        return Err(Error::Invalid);
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(request.into_body(), MAX_BYTES),
    )
    .await
    .map_err(|_| Error::Invalid)?
    .map(|b| b.to_vec())
    .map_err(|_| Error::Invalid)
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Invalid => (StatusCode::BAD_REQUEST, "definition_invalid"),
            Self::Conflict => (StatusCode::CONFLICT, "definition_conflict"),
            Self::NotFound => (StatusCode::NOT_FOUND, "definition_not_found"),
            Self::Backend => (StatusCode::INTERNAL_SERVER_ERROR, "definition_unavailable"),
        };
        (
            status,
            Json(json!({"error":{"code":code,"message":self.to_string()}})),
        )
            .into_response()
    }
}
