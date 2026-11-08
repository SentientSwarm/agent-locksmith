use super::{context::Context, error::Failure, input::Input};
use crate::app::AppState;
use axum::{
    extract::{Path, Request, State},
    response::Response,
};
use std::sync::{Arc, atomic::Ordering};
use tokio_util::sync::CancellationToken;

pub async fn endpoint(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    req: Request,
) -> Response {
    match run(state, name, req, super::compact::Facade::Standard).await {
        Ok(r) => r,
        Err(f) => f.response(),
    }
}
pub async fn compact_endpoint(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    req: Request,
) -> Response {
    match run(state, name, req, super::compact::Facade::Compact).await {
        Ok(r) => r,
        Err(f) => f.response(),
    }
}
async fn run(
    state: Arc<AppState>,
    name: String,
    req: Request,
    facade: super::compact::Facade,
) -> Result<Response, Failure> {
    let identity = super::input::identity(&req)?;
    let token = super::input::cancellation(&req)?;
    let scope = state.native.admit(&identity, &name, facade).await?;
    let input = match Input::read(req, state.native.config.request_bytes).await {
        Ok(input) => input,
        Err(response) => return Ok(*response),
    };
    let mut candidate = Context::new(
        Arc::downgrade(&state.native),
        identity,
        name,
        scope,
        token.clone(),
    );
    candidate.facade = facade;
    let candidate = Arc::new(candidate);
    let context = super::scope::select(
        &state.native,
        candidate,
        &input.request,
        input.value.as_ref(),
    )?;
    admitted(&state, context, input, token).await
}
async fn admitted(
    state: &AppState,
    context: Arc<Context>,
    input: Input,
    token: CancellationToken,
) -> Result<Response, Failure> {
    let guard = context.cancelled.clone().drop_guard();
    context.current().await?;
    if let Some(id) = input.value.as_ref().and_then(|v| v.get("id")) {
        context.remember(id, state.native.config.messages)?;
    }
    let initialized = input
        .value
        .as_ref()
        .is_some_and(|v| v["method"] == "notifications/initialized");
    let response = super::sdk::dispatch(state, context.clone(), input.request, token).await?;
    if initialized && response.status() == 202 {
        context.ready.store(true, Ordering::SeqCst);
    }
    guard.disarm();
    Ok(response)
}
