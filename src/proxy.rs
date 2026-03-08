use axum::{
    Json,
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use reqwest::Client;
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

use crate::app::AppState;
use crate::config::ToolConfig;

pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path((tool_name, path)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    let config = state.config.load();

    // Find the tool
    let tool = match config
        .active_tools()
        .into_iter()
        .find(|t| t.name == tool_name)
    {
        Some(t) => t,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": {
                        "message": format!("Unknown tool: {}", tool_name),
                        "type": "not_found"
                    }
                })),
            )
                .into_response();
        }
    };

    let upstream_url = format!("{}/{}", tool.upstream.trim_end_matches('/'), path);
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": {"message": "Failed to read request body", "type": "bad_request"}})),
            )
                .into_response();
        }
    };

    let client = build_client(tool, &config);
    let mut upstream_req = client.request(method, &upstream_url);

    // Forward headers, stripping auth-related ones
    let auth_header_name = tool.auth.as_ref().map(|a| a.header.to_lowercase());
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_lowercase();
        if lower == "host"
            || lower == "authorization"
            || lower == "x-api-key"
            || auth_header_name.as_deref() == Some(&lower)
        {
            continue;
        }
        upstream_req = upstream_req.header(name, value);
    }

    // Inject configured credentials
    if let Some(auth) = &tool.auth {
        upstream_req = upstream_req.header(&auth.header, auth.value.expose_secret());
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes);
    }

    match upstream_req.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response_headers = HeaderMap::new();
            for (name, value) in resp.headers() {
                if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
                    response_headers.insert(name.clone(), v);
                }
            }
            let body = resp.bytes().await.unwrap_or_default();
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = status;
            *response.headers_mut() = response_headers;
            response
        }
        Err(e) => {
            if e.is_timeout() {
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(json!({"error": {"message": "Upstream timeout", "type": "timeout"}})),
                )
                    .into_response()
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": {"message": "Upstream error", "type": "upstream_error"}})),
                )
                    .into_response()
            }
        }
    }
}

fn build_client(tool: &ToolConfig, config: &crate::config::AppConfig) -> Client {
    let mut builder = Client::builder().timeout(Duration::from_secs(tool.timeout_seconds));

    if tool.cloud
        && let Some(proxy_url) = &config.egress_proxy
        && let Ok(proxy) = reqwest::Proxy::all(proxy_url)
    {
        builder = builder.proxy(proxy);
    }

    builder.build().unwrap_or_else(|_| Client::new())
}
