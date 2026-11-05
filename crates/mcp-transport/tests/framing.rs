mod support;
use futures_util::StreamExt;
use rmcp::transport::streamable_http_client::StreamableHttpPostResponse;
use support::*;

#[tokio::test]
async fn contradictory_transfer_and_length_are_rejected() -> Result<(), Error> {
    let bytes = json(128);
    let chunked = format!("80\r\n{}\r\n0\r\n\r\n", String::from_utf8(bytes)?).into_bytes();
    let reply = Reply::body("application/json", chunked)
        .header("Transfer-Encoding", "chunked")
        .header("Content-Length", "128");
    let server = Server::start(reply).await;
    let c = client(limits(1024));
    assert!(post(&c, &server).await.is_err(), "TE+CL was accepted");
    assert_eq!(c.metrics().snapshot().received, 0);
    Ok(())
}

#[tokio::test]
async fn unsupported_transfer_encoding_is_rejected() -> Result<(), Error> {
    for encoding in ["gzip", "gzip, chunked"] {
        let reply =
            Reply::body("application/json", json(128)).header("Transfer-Encoding", encoding);
        let server = Server::start(reply).await;
        let c = client(limits(1024));
        assert!(post(&c, &server).await.is_err(), "accepted {encoding}");
        assert_eq!(c.metrics().snapshot().received, 0);
    }
    Ok(())
}

#[tokio::test]
async fn bare_cr_never_exposes_an_event_above_the_cap() -> Result<(), Error> {
    let data = String::from_utf8(json(128))?;
    let body = format!("data: {data}\r\rdata: {data}\r\r").into_bytes();
    let server = Server::start(Reply::body("text/event-stream", body)).await;
    let c = client(locksmith_mcp_transport::Limits {
        events: 1,
        ..limits(1024)
    });
    let StreamableHttpPostResponse::Sse(mut stream, _) = post(&c, &server).await? else {
        panic!("SSE expected");
    };
    let mut emitted = 0;
    while let Some(event) = stream.next().await {
        if event.is_err() {
            break;
        }
        emitted += 1;
        assert!(emitted <= 1, "guard exposed second bare-CR event");
    }
    Ok(())
}
