//! Uniform admin error envelope (docs/user/concepts/error-envelope.md).
//!
//! Admin handlers build `{"error":{"code","message"}}` in many places. The
//! documented contract is three fields on every error response, so this
//! response layer fills a missing `error.type` from the HTTP status. It
//! never changes `code`, `message` or an existing `type`, never touches a
//! success response, and leaves bodies it cannot read as small JSON alone.
//! It is mounted on the admin and bootstrap-only routers only: agent-listener
//! responses can carry upstream bodies, which must pass through unchanged.

use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use serde_json::Value;

/// Largest error body this layer will read; larger bodies pass through.
const MAX_ERROR_BODY: usize = 64 * 1024;

/// The documented `type` for an admin error with this status.
pub fn type_for(status: StatusCode) -> &'static str {
    match status.as_u16() {
        401 => "auth_error",
        403 => "authz_error",
        404 => "not_found",
        408 | 504 => "timeout",
        409 => "conflict",
        428 => "precondition_required",
        429 => "rate_limited",
        502 => "upstream_error",
        503 => "unavailable",
        500..=599 => "internal_error",
        _ => "bad_request",
    }
}

/// Response layer: add `error.type` to a JSON error envelope that lacks it.
pub async fn fill_error_type(response: Response) -> Response {
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) || !is_json(&response) {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_ERROR_BODY).await else {
        // Unreadable or oversized: the body is gone, so answer with a
        // minimal envelope rather than an empty error.
        parts.headers.remove(header::CONTENT_LENGTH);
        let body = serde_json::json!({"error": {"type": type_for(status), "code": "internal_error",
            "message": "error response unavailable"}});
        return Response::from_parts(parts, Body::from(body.to_string()));
    };
    let Some(filled) = with_type(&bytes, status) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(filled))
}

fn is_json(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v: &HeaderValue| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"))
}

/// The body with `error.type` filled, or None when it needs no change.
fn with_type(bytes: &[u8], status: StatusCode) -> Option<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(bytes).ok()?;
    let error = value.get_mut("error")?.as_object_mut()?;
    if error.contains_key("type") || !error.get("code").is_some_and(Value::is_string) {
        return None;
    }
    error.insert("type".into(), Value::from(type_for(status)));
    serde_json::to_vec(&value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::response::IntoResponse;
    use serde_json::json;

    async fn run(status: StatusCode, body: Value) -> Value {
        let response = fill_error_type((status, Json(body)).into_response()).await;
        let bytes = to_bytes(response.into_body(), MAX_ERROR_BODY)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn fills_a_missing_type_from_the_status() {
        let out = run(
            StatusCode::UNAUTHORIZED,
            json!({"error":{"code":"invalid_credential","message":"m"}}),
        )
        .await;
        assert_eq!(
            out,
            json!({"error":{"type":"auth_error","code":"invalid_credential","message":"m"}})
        );
        let out = run(
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"definition_not_found"}}),
        )
        .await;
        assert_eq!(out["error"]["type"], "not_found");
    }

    #[tokio::test]
    async fn keeps_an_existing_type_and_extra_fields() {
        let body = json!({"saved":true,"error":{"type":"oauth_consent","code":"x","message":"m"}});
        assert_eq!(run(StatusCode::CONFLICT, body.clone()).await, body);
        let out = run(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"saved":true,"error":{"code":"definition_unavailable"}}),
        )
        .await;
        assert_eq!(out["saved"], true);
        assert_eq!(out["error"]["type"], "unavailable");
    }

    #[tokio::test]
    async fn leaves_success_and_non_envelope_bodies_alone() {
        assert_eq!(
            run(StatusCode::OK, json!({"error":{"code":"x"}})).await,
            json!({"error":{"code":"x"}})
        );
        assert_eq!(
            run(StatusCode::BAD_REQUEST, json!({"error":"plain"})).await,
            json!({"error":"plain"})
        );
        assert_eq!(
            run(StatusCode::BAD_REQUEST, json!({"error":{"code":7}})).await,
            json!({"error":{"code":7}})
        );
    }

    #[test]
    fn status_mapping_matches_the_documented_types() {
        assert_eq!(type_for(StatusCode::BAD_REQUEST), "bad_request");
        assert_eq!(type_for(StatusCode::FORBIDDEN), "authz_error");
        assert_eq!(
            type_for(StatusCode::PRECONDITION_REQUIRED),
            "precondition_required"
        );
        assert_eq!(
            type_for(StatusCode::INTERNAL_SERVER_ERROR),
            "internal_error"
        );
        assert_eq!(type_for(StatusCode::BAD_GATEWAY), "upstream_error");
    }
}
