const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/native_dispatch/receiver.py"
);
use crate::{Error, fixture::Fixture, wire::Wire};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn ingress_body_time_remains_charged_during_final_pool_wait() -> Result<(), Error> {
    let f = Fixture::configured(SCRIPT, 900).await?;
    let w = Wire::open(&f, 0).await?;
    w.list(1).await?;
    f.core.prepared.enable();
    let started = tokio::time::Instant::now();
    let response = delayed_call(&w, &f).await?;
    let mut held = Vec::new();
    for _ in 0..f.core.store.pool.options().get_max_connections() {
        held.push(f.core.store.pool.acquire().await?);
    }
    f.core.prepared.resume();
    let text = tokio::time::timeout(Duration::from_millis(750), response.text()).await??;
    assert!(text.contains("operation_deadline"), "{text}");
    assert!(
        started.elapsed() < Duration::from_millis(1250),
        "handler must not reset the 900ms ingress clock"
    );
    assert_eq!(f.core.slots.available_permits(), 8);
    let admitted: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
        .fetch_one(&mut **held.first_mut().unwrap())
        .await?;
    assert_eq!(admitted, 0);
    assert_eq!(f.arrivals()?, 0);
    drop(held);
    f.finish().await
}

async fn delayed_call(w: &Wire, f: &Fixture) -> Result<reqwest::Response, Error> {
    let request = w.clone();
    let pending = tokio::spawn(async move {
        request
            .request(reqwest::Method::POST)
            .header("content-type", "application/json")
            .body(slow_body())
            .send()
            .await
    });
    f.core.prepared.reached().await;
    Ok(pending.await??)
}

fn slow_body() -> reqwest::Body {
    let bytes=json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read","arguments":{"ticket":"late-body"}}}).to_string();
    let (head, tail) = (bytes[..10].to_owned(), bytes[10..].to_owned());
    reqwest::Body::wrap_stream(futures_util::stream::unfold(
        (0, head, tail),
        |(n, a, b)| async move {
            match n {
                0 => Some((Ok::<_, std::io::Error>(a.clone()), (1, a, b))),
                1 => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    Some((Ok(b.clone()), (2, a, b)))
                }
                _ => None,
            }
        },
    ))
}
