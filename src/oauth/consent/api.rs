use super::*;
use crate::auth_v2::OperatorIdentity;
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::time::Duration;

pub fn router(runtime: Arc<Runtime>) -> Router {
    Router::new()
        .route("/tools/{name}/oauth/attempts", post(start))
        .route(
            "/tools/{name}/oauth/attempts/{id}",
            get(poll).delete(cancel),
        )
        .route(
            "/tools/{name}/oauth/accounts/{label}",
            get(account).delete(disconnect),
        )
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(runtime.clone(), bounded))
        .layer(middleware::from_fn(safe))
        .with_state(runtime)
}
pub(super) async fn safe(req: Request, next: Next) -> Response {
    let response = tokio::time::timeout(Duration::from_secs(50), next.run(req))
        .await
        .unwrap_or_else(|_| error(Error("operation_incomplete")));
    headers(response)
}
pub(super) fn headers(mut response: Response) -> Response {
    for (key, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(key),
            axum::http::HeaderValue::from_static(value),
        );
    }
    response
}
fn error(e: Error) -> Response {
    let status = match e.0 {
        "not_found" => StatusCode::NOT_FOUND,
        "source_conflict" | "profile_conflict" | "account_conflict" => StatusCode::CONFLICT,
        "if_match_required" => StatusCode::PRECONDITION_REQUIRED,
        "capacity" => StatusCode::TOO_MANY_REQUESTS,
        "custody_failed" | "sealing_failed" | "operation_incomplete" | "shutting_down" => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::BAD_REQUEST,
    };
    headers((status,Json(json!({"error":{"type":"oauth_consent","code":e.0,"message":"Consent operation refused"}}))).into_response())
}
fn response(result: Result<Value>, status: StatusCode) -> Response {
    match result {
        Ok(v) => (status, Json(v)).into_response(),
        Err(e) => error(e),
    }
}
async fn start(
    State(rt): State<Arc<Runtime>>,
    Extension(owner): Extension<OperatorIdentity>,
    Path(name): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let request = parse(&body)
        .and_then(|v| serde_json::from_value::<Start>(v).map_err(|_| Error("invalid_request")));
    let request = match request {
        Ok(v) => v,
        Err(e) => return error(e),
    };
    response(
        rt.start(&owner.public_id, &name, &request).await,
        StatusCode::CREATED,
    )
}
async fn poll(
    State(rt): State<Arc<Runtime>>,
    Extension(owner): Extension<OperatorIdentity>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    response(rt.poll(&owner.public_id, &name, &id).await, StatusCode::OK)
}
async fn cancel(
    State(rt): State<Arc<Runtime>>,
    Extension(owner): Extension<OperatorIdentity>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    match rt.cancel(&owner.public_id, &name, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error(e),
    }
}
async fn account(
    State(rt): State<Arc<Runtime>>,
    Extension(owner): Extension<OperatorIdentity>,
    Path((name, label)): Path<(String, String)>,
) -> Response {
    response(
        rt.account(&owner.public_id, &name, &label).await,
        StatusCode::OK,
    )
}
async fn disconnect(
    State(rt): State<Arc<Runtime>>,
    Extension(owner): Extension<OperatorIdentity>,
    Path((name, label)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let expected = match headers.get("if-match").and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => return error(Error("if_match_required")),
    };
    response(
        rt.disconnect(&owner.public_id, &name, &label, expected)
            .await,
        StatusCode::OK,
    )
}

/// Apply disclosure headers outside authentication, including rejected requests.
pub async fn protect_errors(req: Request, next: Next) -> Response {
    let consent = req.uri().path().starts_with("/admin/operator/tools/")
        && req.uri().path().contains("/oauth/");
    let response = next.run(req).await;
    if consent { headers(response) } else { response }
}

async fn bounded(State(rt): State<Arc<Runtime>>, req: Request, next: Next) -> Response {
    let Ok(_permit) = rt.operations.try_acquire() else {
        return error(Error("capacity"));
    };
    rt.owner
        .run(next.run(req))
        .await
        .unwrap_or_else(|| error(Error("shutting_down")))
}
