#![allow(dead_code)]
mod raw;
use locksmith_mcp_transport::{Client, Limits};
pub use raw::*;
use rmcp::{model::*, transport::streamable_http_client::*};
use std::{collections::HashMap, sync::Arc};
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub fn client(limits: Limits) -> Client {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Client::new(limits, vec![]).unwrap()
}
pub fn ping() -> ClientJsonRpcMessage {
    ClientJsonRpcMessage::request(
        ClientRequest::PingRequest(PingRequest::default()),
        RequestId::Number(1),
    )
}
pub async fn post(
    client: &Client,
    server: &Server,
) -> Result<StreamableHttpPostResponse, StreamableHttpError<locksmith_mcp_transport::Error>> {
    client
        .post_message(
            Arc::from(server.url.as_str()),
            ping(),
            None,
            None,
            HashMap::new(),
        )
        .await
}
pub fn json(size: usize) -> Vec<u8> {
    let prefix = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":""#;
    let suffix = br#""}]}}"#;
    let mut result = prefix.to_vec();
    result.extend(vec![b'x'; size - prefix.len() - suffix.len()]);
    result.extend_from_slice(suffix);
    result
}
pub fn limits(cap: usize) -> Limits {
    Limits {
        response_bytes: cap,
        ..Default::default()
    }
}
pub async fn drain(reply: StreamableHttpPostResponse) -> Result<usize, Error> {
    use futures_util::StreamExt;
    let StreamableHttpPostResponse::Sse(mut stream, _) = reply else {
        panic!("SSE expected");
    };
    let mut count = 0;
    while let Some(event) = stream.next().await {
        event?;
        count += 1;
    }
    Ok(count)
}

pub mod process;
