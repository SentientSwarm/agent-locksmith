//! Test-side provider is a separate process from the actual daemon under test.
use super::upstream;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicU8, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
struct StateData {
    mode: AtomicU8,
    expiry: AtomicI64,
    arrived: Notify,
    release: Notify,
}
pub struct Provider {
    pub url: String,
    state: Arc<StateData>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Provider {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(StateData::default());
        state.expiry.store(3600, Ordering::SeqCst);
        let app = Router::new()
            .route("/token", post(token))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, state, task }
    }
    pub fn expiry(&self, seconds: i64) {
        self.state.expiry.store(seconds, Ordering::SeqCst);
    }
    pub fn hold(&self, fail: bool) {
        self.state
            .mode
            .store(if fail { 2 } else { 1 }, Ordering::SeqCst);
    }
    pub async fn arrived(&self) {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.state.arrived.notified(),
        )
        .await
        .unwrap();
    }
    pub fn release(&self) {
        self.state.release.notify_one();
    }
}
async fn token(State(state): State<Arc<StateData>>) -> Response {
    let mode = state.mode.swap(0, Ordering::SeqCst);
    if mode != 0 {
        state.arrived.notify_one();
        state.release.notified().await;
    }
    if mode == 2 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    Json(serde_json::json!({
        "access_token": if mode == 1 { upstream::X } else { upstream::Y },
        "refresh_token": "synthetic-rotated-refresh",
        "expires_in": state.expiry.load(Ordering::SeqCst), "token_type": "Bearer",
    }))
    .into_response()
}
