use crate::native_authority::{api, body_probe, body_scope, runtime::Runtime};
use crate::oauth::refresh::RefreshOwner;
use axum::{body::Body, extract::Request};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::task::JoinHandle;

pub fn request(key: &str, body: Body) -> Request {
    Request::builder()
        .header("content-type", "application/json")
        .header("x-native-body-test", key)
        .body(body)
        .unwrap()
}
pub fn pending_body() -> Body {
    Body::from_stream(futures_util::stream::pending::<
        Result<bytes::Bytes, std::io::Error>,
    >())
}
pub fn spawn(owner: RefreshOwner, key: String) -> JoinHandle<super::super::Result<Value>> {
    tokio::spawn(async move {
        body_scope::run(&owner, async {
            api::body::<Value>(request(&key, pending_body())).await
        })
        .await
    })
}
pub async fn entered(probe: &body_probe::Probe) {
    tokio::time::timeout(Duration::from_secs(2), probe.entered())
        .await
        .unwrap();
}
pub async fn join(task: JoinHandle<super::super::Result<Value>>) {
    task.abort();
    let _ = task.await;
}
pub fn runtime(owner: RefreshOwner) -> Runtime {
    Runtime {
        repo: Arc::new(crate::registrations::RegistrationRepository::new(
            sqlx::sqlite::SqlitePoolOptions::new()
                .connect_lazy("sqlite::memory:")
                .unwrap(),
        )),
        catalog: Arc::new(arc_swap::ArcSwap::from_pointee(Default::default())),
        key: None,
        roots: vec![],
        run: "body-clock-fixture".into(),
        listeners: Default::default(),
        owner,
        slots: tokio::sync::Semaphore::new(8),
    }
}
