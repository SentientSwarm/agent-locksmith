#[path = "native/fixture.rs"]
mod fixture;
use axum::{
    body::{Body, Bytes},
    http::Request,
};
use fixture::*;
use secrecy::ExposeSecret;
use serde_json::json;
use tower::ServiceExt;

fn delayed(
    f: &Fixture,
    started: tokio::sync::oneshot::Sender<()>,
    finish: tokio::sync::oneshot::Receiver<()>,
) -> Request<Body> {
    let stream = futures_util::stream::once(async move {
        let _ = started.send(());
        let _ = finish.await;
        Ok::<_, std::io::Error>(Bytes::from(init(0).to_string()))
    });
    Request::builder()
        .method("POST")
        .uri("/mcp/native")
        .header("host", "localhost")
        .header("authorization", &f.bearer)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from_stream(stream))
        .unwrap()
}
#[tokio::test]
async fn binding_removed_during_actual_body_wait_prevents_allocation() {
    let f = Fixture::new("").await;
    let (enter, entered) = tokio::sync::oneshot::channel();
    let (finish, finished) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(f.app.clone().oneshot(delayed(&f, enter, finished)));
    entered.await.unwrap();
    f.bindings.delete(f.agent_id, "native").await.unwrap();
    finish.send(()).unwrap();
    assert_eq!(task.await.unwrap().unwrap().status(), 404);
    assert_eq!(f.runtime.snapshot().workers_created, 0);
}
#[tokio::test]
async fn expired_body_deadline_never_allocates_after_late_body() {
    let f = Fixture::new("mcp:\n  request_ms: 150\n").await;
    let (enter, entered) = tokio::sync::oneshot::channel();
    let (finish, finished) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(f.app.clone().oneshot(delayed(&f, enter, finished)));
    entered.await.unwrap();
    assert_eq!(task.await.unwrap().unwrap().status(), 408);
    assert!(finish.send(()).is_err());
    assert_eq!(f.runtime.snapshot().workers_created, 0);
}
#[tokio::test]
async fn foreign_agent_cannot_use_or_retire_owner_session() {
    let f = Fixture::new("").await;
    let session = f.open().await;
    let bearer = foreign(&f).await;
    for method in ["GET", "DELETE", "POST"] {
        let req = foreign_request(method, &bearer, &session);
        assert_eq!(f.app.clone().oneshot(req).await.unwrap().status(), 404);
    }
    assert_eq!(
        rpc(f.call(&session, 1, "ping").await).await["result"],
        json!({})
    );
    f.runtime.shutdown().await;
}
#[tokio::test]
async fn current_expiry_and_idle_invalidation_release_owned_resources() {
    let f = Fixture::new("").await;
    let _session = f.open().await;
    let stop = tokio_util::sync::CancellationToken::new();
    let task = f.runtime.start(stop.clone().cancelled_owned());
    sqlx::query("UPDATE agents SET expires_at=1 WHERE id=?")
        .bind(f.agent_id)
        .execute(&f.pool)
        .await
        .unwrap();
    released(&f).await;
    assert_eq!(
        f.request("/mcp/native", "POST", init(0), None)
            .await
            .status(),
        401
    );
    stop.cancel();
    task.await.unwrap();
    let s = f.runtime.snapshot();
    assert_eq!(s.workers_created, s.workers_joined);
    assert_eq!(s.services_created, s.services_joined);
}

fn foreign_request(method: &str, bearer: &str, session: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri("/mcp/native")
        .header("host", "localhost")
        .header("authorization", bearer)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-session-id", session)
        .header("mcp-protocol-version", "2025-11-25")
        .body(if method == "POST" {
            Body::from(json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string())
        } else {
            Body::empty()
        })
        .unwrap()
}

async fn foreign(f: &Fixture) -> String {
    let (id, secret) = f
        .agents
        .create("foreign", None, Some(&["native".into()]), None, None, None)
        .await
        .unwrap();
    let agent = f.agents.get_by_name("foreign").await.unwrap().unwrap();
    f.bindings
        .set(
            agent.id,
            "native",
            &agent_locksmith::registrations::AuthSpec::None,
        )
        .await
        .unwrap();
    format!("Bearer lk_{id}.{}", secret.expose_secret())
}
