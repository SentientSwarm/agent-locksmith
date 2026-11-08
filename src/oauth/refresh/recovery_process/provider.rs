use axum::{
    Form, Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;

struct Data {
    arrivals: AtomicUsize,
    consumed: AtomicUsize,
    issued: AtomicUsize,
    hold: bool,
    release: Arc<Notify>,
}
pub struct Provider {
    pub url: String,
    pub release: Arc<Notify>,
    data: Arc<Data>,
    cancel: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Provider {
    pub async fn new(hold: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let release = Arc::new(Notify::new());
        let data = Arc::new(Data {
            arrivals: AtomicUsize::new(0),
            consumed: AtomicUsize::new(0),
            issued: AtomicUsize::new(0),
            hold,
            release: release.clone(),
        });
        let app = Router::new()
            .route("/token", post(token))
            .with_state(data.clone());
        let cancel = tokio_util::sync::CancellationToken::new();
        let stopped = cancel.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stopped.cancelled_owned())
                .await
                .unwrap();
        });
        Self {
            url,
            release,
            data,
            cancel,
            task,
        }
    }
    pub fn arrivals(&self) -> usize {
        self.data.arrivals.load(Ordering::SeqCst)
    }
    pub fn consumed(&self) -> usize {
        self.data.consumed.load(Ordering::SeqCst)
    }
    pub fn issued(&self) -> usize {
        self.data.issued.load(Ordering::SeqCst)
    }
    pub async fn stop(self) {
        self.cancel.cancel();
        self.task.await.unwrap();
    }
}
async fn token(
    State(s): State<Arc<Data>>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    s.arrivals.fetch_add(1, Ordering::SeqCst);
    if form.get("refresh_token").map(String::as_str) != Some("synthetic-old-refresh")
        || s.consumed
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if s.hold {
        s.release.notified().await;
        return StatusCode::BAD_GATEWAY.into_response();
    }
    s.issued.fetch_add(1, Ordering::SeqCst);
    Json(serde_json::json!({"access_token":"synthetic-new-access", "refresh_token":"synthetic-new-refresh", "expires_in":3600})).into_response()
}
