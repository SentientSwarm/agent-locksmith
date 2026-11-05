mod support;
use futures_util::StreamExt;
use rmcp::transport::streamable_http_client::StreamableHttpClient;
use std::{collections::HashMap, sync::Arc, time::Duration};
use support::*;

#[tokio::test]
async fn sse_whole_response_does_not_reset_for_comments() -> Result<(), Error> {
    let mut reply = Reply::body("text/event-stream", Vec::new());
    reply.parts = vec![b": ping\n\n".to_vec(); 100];
    reply.delay = Duration::from_millis(1);
    let server = Server::start(reply).await;
    let c = client(limits(128));
    assert!(drain(post(&c, &server).await?).await.is_err());
    assert!(c.metrics().snapshot().admitted <= 128);
    assert_eq!(c.metrics().snapshot().active_bodies, 0);
    Ok(())
}
#[tokio::test]
async fn event_boundaries_crlf_and_multibyte() -> Result<(), Error> {
    let data = String::from_utf8(json(128))?.replace('x', "é");
    let body = format!("data: {data}\r\n\r\n").into_bytes();
    for cap in [body.len() - 1, body.len(), body.len() + 1] {
        let mut reply = Reply::body("text/event-stream", Vec::new());
        reply.parts = body.chunks(1).map(|b| b.to_vec()).collect();
        let server = Server::start(reply).await;
        let c = client(locksmith_mcp_transport::Limits {
            event_bytes: cap,
            ..limits(4096)
        });
        assert_eq!(
            drain(post(&c, &server).await?).await.is_ok(),
            cap >= body.len()
        );
    }
    Ok(())
}
#[tokio::test]
async fn many_blocks_and_truncation_fail() -> Result<(), Error> {
    for bytes in [
        b":x\n\n".repeat(5),
        b"data: {}".to_vec(),
        b"data: {bad}\n\n".to_vec(),
    ] {
        let c = client(locksmith_mcp_transport::Limits {
            events: 4,
            ..limits(512)
        });
        let s = Server::start(Reply::body("text/event-stream", bytes)).await;
        assert!(drain(post(&c, &s).await?).await.is_err());
    }
    Ok(())
}
#[tokio::test]
async fn get_uses_same_limits_and_resume_is_explicit() -> Result<(), Error> {
    let server = Server::start(Reply::body("text/event-stream", b":x\n\n".repeat(100))).await;
    let c = client(limits(256));
    let mut stream = c
        .get_stream(
            Arc::from(server.url.as_str()),
            None,
            None,
            None,
            HashMap::new(),
        )
        .await?;
    assert!(stream.next().await.unwrap().is_err());
    drop(stream);
    assert!(
        c.get_stream(
            Arc::from(server.url.as_str()),
            None,
            Some("cursor".into()),
            None,
            HashMap::new()
        )
        .await
        .is_err()
    );
    assert_eq!(server.hits(), 1);
    assert_eq!(c.metrics().snapshot().active_bodies, 0);
    Ok(())
}
