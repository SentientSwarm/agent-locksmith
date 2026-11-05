//! One-use receiving observer stays alive while disposable daemons are killed.
use axum::{
    Form, Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::Notify;

#[derive(Default)]
struct Data {
    used: Mutex<HashSet<String>>,
    arrivals: AtomicUsize,
    issued: AtomicUsize,
    hold: AtomicBool,
    arrived: Notify,
    release: Notify,
}
pub struct Provider {
    pub url: String,
    data: Arc<Data>,
    cancel: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Provider {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let data = Arc::new(Data::default());
        let app = Router::new()
            .route("/token", post(token))
            .with_state(data.clone());
        let cancel = tokio_util::sync::CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
                .unwrap();
        });
        Self {
            url,
            data,
            cancel,
            task,
        }
    }
    pub fn hold(&self) {
        self.data.hold.store(true, Ordering::SeqCst);
    }
    pub async fn arrived(&self) {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.data.arrived.notified(),
        )
        .await
        .unwrap();
    }
    pub fn release(&self) {
        self.data.release.notify_one();
    }
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.data.arrivals.load(Ordering::SeqCst),
            self.data.used.lock().unwrap().len(),
            self.data.issued.load(Ordering::SeqCst),
        )
    }
    pub async fn stop(self) {
        self.cancel.cancel();
        self.task.await.unwrap();
    }
}
async fn token(State(s): State<Arc<Data>>, Form(form): Form<HashMap<String, String>>) -> Response {
    s.arrivals.fetch_add(1, Ordering::SeqCst);
    let Some(token) = form.get("refresh_token") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !s.used.lock().unwrap().insert(token.clone()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if s.hold.swap(false, Ordering::SeqCst) {
        s.arrived.notify_one();
        s.release.notified().await;
    }
    let version = s.issued.fetch_add(1, Ordering::SeqCst) + 1;
    Json(serde_json::json!({"access_token":super::upstream::Y,
        "refresh_token":format!("synthetic-rotation-{version}"), "expires_in":3600}))
    .into_response()
}
