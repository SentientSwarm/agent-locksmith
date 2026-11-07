use super::{context::Context, error::Failure, handler::Handler, manager::Manager};
use crate::app::AppState;
use axum::{body::Body, extract::Request, response::Response};
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
pub(super) async fn dispatch(
    state: &AppState,
    context: Arc<Context>,
    req: Request,
    token: CancellationToken,
) -> Result<Response, Failure> {
    let status = Arc::new(AtomicU16::new(0));
    let manager = manager(state, &context, status.clone())?;
    let audit = state.audit.clone();
    let sdk = StreamableHttpService::new(
        move || Ok(Handler(context.clone(), audit.clone())),
        manager,
        config(state),
    );
    let response = tokio::select! {
        biased;
        _ = token.cancelled() => return Err(Failure(408,"request_cancelled")),
        result = sdk.oneshot(req) => result.expect("SDK infallible service"),
    };
    checked(response.map(Body::new), &status)
}
fn manager(
    state: &AppState,
    context: &Arc<Context>,
    status: Arc<AtomicU16>,
) -> Result<Arc<Manager>, Failure> {
    let inner = state
        .native
        .pool
        .scoped(
            context.scope.clone(),
            context.clone(),
            context.cancelled.clone(),
        )
        .map_err(|_| Failure(503, "native_scope_unavailable"))?;
    Ok(Arc::new(Manager { inner, status }))
}
fn config(state: &AppState) -> StreamableHttpServerConfig {
    let mut config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(state.native.config.allowed_hosts.clone());
    config.sse_keep_alive = None;
    config.sse_retry = None;
    config.cancellation_token = state.native.stopped.clone();
    config.max_request_body_bytes = state.native.config.request_bytes;
    config
}
fn checked(response: Response, status: &AtomicU16) -> Result<Response, Failure> {
    let mapped = status.load(Ordering::SeqCst);
    if mapped != 0 {
        return Err(Failure(
            mapped,
            if mapped == 429 {
                "session_limit"
            } else {
                "session_unavailable"
            },
        ));
    }
    if response.status().is_client_error() || response.status().is_server_error() {
        return Err(Failure(
            response.status().as_u16(),
            "protocol_request_refused",
        ));
    }
    Ok(response)
}
