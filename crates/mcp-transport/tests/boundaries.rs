mod support;
use rmcp::transport::streamable_http_client::StreamableHttpPostResponse;
use support::*;

#[tokio::test]
async fn whole_json_boundary_and_tail() -> Result<(), Error> {
    for size in [255, 256, 257] {
        for declared in [false, true] {
            let mut reply = Reply::body("application/json", json(size));
            if declared {
                reply = reply.header("Content-Length", &size.to_string());
            }
            let server = Server::start(reply).await;
            let client = client(limits(256));
            assert_eq!(post(&client, &server).await.is_ok(), size <= 256);
            assert!(client.metrics().snapshot().retained_high_water <= 256);
        }
    }
    let mut body = json(128);
    body.extend(vec![b' '; 129]);
    let server = Server::start(Reply::body("application/json", body)).await;
    assert!(post(&client(limits(256)), &server).await.is_err());
    Ok(())
}
#[tokio::test]
async fn chunked_and_close_delimited_bounds() -> Result<(), Error> {
    for size in [256, 257] {
        let mut reply =
            Reply::body("application/json", Vec::new()).header("Transfer-Encoding", "chunked");
        reply.parts = json(size)
            .chunks(7)
            .map(|part| {
                let mut b = format!("{:x}\r\n", part.len()).into_bytes();
                b.extend(part);
                b.extend(b"\r\n");
                b
            })
            .collect();
        reply.parts.push(b"0\r\n\r\n".to_vec());
        let server = Server::start(reply).await;
        assert_eq!(
            post(&client(limits(256)), &server).await.is_ok(),
            size == 256
        );
    }
    Ok(())
}
#[tokio::test]
async fn false_length_and_malformed_bodies_fail() -> Result<(), Error> {
    let replies = [
        Reply::body("application/json", json(128)).header("Content-Length", "200"),
        Reply::body("application/json", json(128)).header("Content-Length", "12"),
        Reply::body("application/json", b"{bad CANARY}".to_vec()),
        Reply::body("application/json", b"{}junk".to_vec()),
        Reply::body("application/json", vec![0xff]),
        Reply::body("application/json", b"z\r\ninvalid\r\n".to_vec())
            .header("Transfer-Encoding", "chunked"),
    ];
    for reply in replies {
        let error = post(&client(limits(512)), &Server::start(reply).await)
            .await
            .unwrap_err();
        assert!(!format!("{error:?}").contains("CANARY"));
    }
    Ok(())
}
#[tokio::test]
async fn errors_and_unsupported_encodings_are_bounded() -> Result<(), Error> {
    for status in ["400 Bad Request", "500 Internal Server Error"] {
        let mut reply = Reply::body("application/json", json(257));
        reply.head = reply.head.replace("200 OK", status);
        let error = post(&client(limits(256)), &Server::start(reply).await)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("response_bytes"));
    }
    for encoding in ["gzip", "br", "deflate", "zstd", "identity, gzip"] {
        let server = Server::start(
            Reply::body("application/json", json(128)).header("Content-Encoding", encoding),
        )
        .await;
        let c = client(limits(256));
        assert!(
            post(&c, &server)
                .await
                .unwrap_err()
                .to_string()
                .contains("content_encoding")
        );
        assert_eq!(c.metrics().snapshot().received, 0);
    }
    Ok(())
}
#[tokio::test]
async fn bounded_json_rpc_error_preserves_semantics() -> Result<(), Error> {
    let mut reply = Reply::body(
        "application/json",
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid arguments"}}"#
            .to_vec(),
    );
    reply.head = reply.head.replace("200 OK", "400 Bad Request");
    let result = post(&client(limits(256)), &Server::start(reply).await).await?;
    assert!(matches!(
        result,
        StreamableHttpPostResponse::Json(rmcp::model::ServerJsonRpcMessage::Error(_), _)
    ));
    Ok(())
}
