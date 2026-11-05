mod support;
use locksmith_mcp_transport::Limits;
use support::*;

#[tokio::test]
async fn exact_lexical_units_and_depth_boundaries() -> Result<(), Error> {
    let bytes = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec();
    for units in [13, 14, 15] {
        let c = client(Limits {
            json_units: units,
            ..limits(256)
        });
        let s = Server::start(Reply::body("application/json", bytes.clone())).await;
        assert_eq!(post(&c, &s).await.is_ok(), units >= 14);
    }
    for depth in [1, 2, 3] {
        let c = client(Limits {
            json_depth: depth,
            ..limits(256)
        });
        let s = Server::start(Reply::body("application/json", bytes.clone())).await;
        assert_eq!(post(&c, &s).await.is_ok(), depth >= 2);
    }
    Ok(())
}
#[tokio::test]
async fn quoted_delimiters_and_escapes_are_not_structure() -> Result<(), Error> {
    let value = serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"content":[
        {"type":"text","text":"[{}] , : \" \\ \u{00e9}".repeat(20)}]}});
    let c = client(Limits {
        json_depth: 4,
        json_units: 32,
        ..limits(4096)
    });
    let s = Server::start(Reply::body("application/json", serde_json::to_vec(&value)?)).await;
    assert!(post(&c, &s).await.is_ok());
    Ok(())
}

#[tokio::test]
async fn unsupported_negotiated_version_is_not_silently_used() -> Result<(), Error> {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"result":{
        "protocolVersion":"2099-01-01","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}});
    let s = Server::start(Reply::body("application/json", serde_json::to_vec(&body)?)).await;
    assert!(
        post(&client(limits(1024)), &s)
            .await
            .unwrap_err()
            .to_string()
            .contains("protocol_version")
    );
    Ok(())
}
