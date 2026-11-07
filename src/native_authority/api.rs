use super::{Error, Result, body_scope, runtime::Runtime, writes};
use crate::{admin::uds::UdsState, auth_v2::OperatorIdentity};
use axum::{
    Extension, Json, Router,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::sync::Arc;

pub fn router(state: UdsState) -> Router {
    Router::new()
        .route(
            "/tools/{name}/mcp/observations/{agent}",
            get(show).post(observe),
        )
        .route(
            "/tools/{name}/mcp/reviews/{agent}",
            axum::routing::put(review),
        )
        .route(
            "/agents/{agent}/mcp-grants/{name}",
            get(grants).put(replace),
        )
        .route(
            "/agents/{agent}/oauth-selection/{name}",
            axum::routing::put(select),
        )
        .with_state(state)
}
fn runtime(state: &UdsState) -> Result<Arc<Runtime>> {
    state
        .admin
        .native_authority()
        .ok_or(Error("native_preparation_unavailable"))
}
async fn show(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((name, agent)): Path<(String, String)>,
) -> Result<Json<Value>> {
    let rt = runtime(&state)?;
    Ok(Json(
        rt.scoped(rt.snapshot_for(Some(&op.public_id), &agent, &name))
            .await?,
    ))
}
async fn grants(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((agent, name)): Path<(String, String)>,
) -> Result<Json<Value>> {
    show(State(state), Extension(op), Path((name, agent))).await
}
async fn observe(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((name, agent)): Path<(String, String)>,
    request: Request,
) -> Result<Json<Value>> {
    let rt = runtime(&state)?;
    Ok(Json(
        body_scope::run(&rt.owner, async {
            let input: writes::Observe = body(request).await?;
            rt.scoped(rt.observe_for(
                Some(&op.public_id),
                &agent,
                &name,
                &input.source,
                input.generation.as_deref(),
            ))
            .await
        })
        .await?,
    ))
}
async fn review(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((name, agent)): Path<(String, String)>,
    request: Request,
) -> Result<Json<Value>> {
    let rt = runtime(&state)?;
    Ok(Json(
        body_scope::run(&rt.owner, async {
            let input = body(request).await?;
            rt.scoped(rt.review_for(Some(&op.public_id), &agent, &name, input))
                .await
        })
        .await?,
    ))
}
async fn replace(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((agent, name)): Path<(String, String)>,
    request: Request,
) -> Result<Json<Value>> {
    let rt = runtime(&state)?;
    Ok(Json(
        body_scope::run(&rt.owner, async {
            let input = body(request).await?;
            rt.scoped(rt.replace_for(Some(&op.public_id), &agent, &name, input))
                .await
        })
        .await?,
    ))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    label: String,
}
async fn select(
    State(state): State<UdsState>,
    Extension(op): Extension<OperatorIdentity>,
    Path((agent, name)): Path<(String, String)>,
    request: Request,
) -> Result<Json<Value>> {
    let expected = request
        .headers()
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .ok_or(Error("if_match_required"))?
        .to_string();
    let rt = runtime(&state)?;
    Ok(Json(
        body_scope::run(&rt.owner, async {
            let input: Selection = body(request).await?;
            rt.scoped(rt.select_oauth(&op.public_id, &agent, &name, &input.label, &expected))
                .await
        })
        .await?,
    ))
}
pub(super) async fn body<T: DeserializeOwned>(request: Request) -> Result<T> {
    if request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim)
        != Some("application/json")
    {
        return Err(Error("json_required"));
    }
    #[cfg(test)]
    let _body_probe = super::body_probe::enter(&request);
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(request.into_body(), 64 * 1024),
    )
    .await
    .map_err(|_| Error("body_deadline"))?
    .map_err(|_| Error("body_limit"))?;
    parse(&bytes)
}
pub fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > 64 * 1024 {
        return Err(Error("body_limit"));
    }
    let value = crate::native::json::parse(bytes).map_err(|_| Error("invalid_json"))?;
    serde_json::from_value(value).map_err(|_| Error("invalid_request"))
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match self.0 {
            "observation_conflict" | "grant_conflict" | "source_conflict" => StatusCode::CONFLICT,
            "if_match_required" => StatusCode::PRECONDITION_REQUIRED,
            "observation_capacity" => StatusCode::TOO_MANY_REQUESTS,
            "agent_not_found" | "not_found" => StatusCode::NOT_FOUND,
            "operation_deadline" | "body_deadline" => StatusCode::REQUEST_TIMEOUT,
            "deadline"
            | "http"
            | "oauth_custody_unavailable"
            | "backend_unavailable"
            | "shutting_down"
            | "native_preparation_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        };
        (
            status,
            Json(json!({"error":{"code":self.0,"message":self.0}})),
        )
            .into_response()
    }
}
