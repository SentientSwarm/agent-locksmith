mod support;
use support::*;

#[tokio::test]
async fn cr_lf_and_crlf_have_exact_block_and_byte_limits() -> Result<(), Error> {
    let data = String::from_utf8(json(128))?;
    for newline in ["\r", "\n", "\r\n"] {
        let block = format!("data: {data}{newline}{newline}").into_bytes();
        for cap in [block.len() - 1, block.len(), block.len() + 1] {
            let mut reply = Reply::body("text/event-stream", Vec::new());
            reply.parts = block.repeat(2).chunks(1).map(|c| c.to_vec()).collect();
            let s = Server::start(reply).await;
            let c = client(locksmith_mcp_transport::Limits {
                events: 2,
                event_bytes: cap,
                ..limits(1024)
            });
            let result = drain(post(&c, &s).await?).await;
            if cap >= block.len() {
                assert_eq!(result?, 2);
            } else {
                assert!(result.is_err());
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn bare_cr_on_chunk_boundaries_cannot_expose_second_event() -> Result<(), Error> {
    use futures_util::StreamExt;
    use rmcp::transport::streamable_http_client::StreamableHttpPostResponse;
    let data = String::from_utf8(json(128))?;
    let mut reply = Reply::body("text/event-stream", Vec::new());
    reply.parts = vec![format!("data: {data}\r\r").into_bytes(); 2];
    reply.delay = std::time::Duration::from_millis(20);
    let s = Server::start(reply).await;
    let c = client(locksmith_mcp_transport::Limits {
        events: 1,
        ..limits(1024)
    });
    let StreamableHttpPostResponse::Sse(mut stream, _) = post(&c, &s).await? else {
        panic!("SSE expected");
    };
    assert!(stream.next().await.unwrap().is_ok());
    assert!(stream.next().await.unwrap().is_err());
    assert_eq!(c.metrics().snapshot().active_bodies, 0);
    Ok(())
}
