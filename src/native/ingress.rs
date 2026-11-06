use super::{error::Failure, response, wire};
use crate::app::AppState;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(super) struct Deadline(pub tokio::time::Instant);

/// Outer native-only guard: includes authenticator DB/Argon2 and body waits.
pub async fn boundary(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if !req.uri().path().starts_with("/mcp/") {
        return next.run(req).await;
    }
    guarded(state, req, next).await
}
async fn guarded(state: Arc<AppState>, mut req: Request, next: Next) -> Response {
    if req.uri().query().is_some() {
        return Failure(400, "query_unsupported").response();
    }
    let native = &state.native;
    if native.stopped.is_cancelled() {
        return Failure(503, "shutting_down").response();
    }
    let Ok(_permit) = native.ingress.try_acquire() else {
        return Failure(429, "ingress_limit").response();
    };
    if let Err(f) = wire::headers(req.headers(), req.method(), &native.config) {
        return f.response();
    }
    let token = CancellationToken::new();
    let guard = token.clone().drop_guard();
    req.extensions_mut().insert(token);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(native.config.request_ms);
    req.extensions_mut().insert(Deadline(deadline));
    let response = tokio::select! {
        biased;
        _ = native.stopped.cancelled() => return Failure(503,"shutting_down").response(),
        result = tokio::time::timeout_at(deadline, next.run(req)) => {
            match result { Ok(r) => r, Err(_) => return Failure(408,"request_deadline").response() }
        }
    };
    guard.disarm();
    response::bounded(response, native.stopped.clone(), native.config.response_ms)
}
