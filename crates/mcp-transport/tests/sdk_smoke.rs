mod support;
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, ClientConfig, ProtocolVersion},
};
use serde_json::json;
use support::{Error, process::Receiver};

fn call(mode: &str) -> CallToolRequestParams {
    serde_json::from_value(json!({"name":"echo","arguments":{"mode":mode}})).unwrap()
}
fn config() -> ClientConfig {
    ClientConfig::default().with_protocol_version(ProtocolVersion::V_2025_11_25)
}
#[tokio::test]
async fn actual_sdk_tls_receiver_bounds_do_not_replay_effects() -> Result<(), Error> {
    let receiver = Receiver::start().await?;
    let client = receiver.client()?;
    let service = config()
        .serve(client.transport(receiver.url.clone(), Some("synthetic-test-token".into())))
        .await?;
    assert_eq!(service.list_tools(None).await?.tools.len(), 1);
    for mode in ["json", "sse", "error"] {
        let response = service.call_tool(call(mode)).await?;
        assert_eq!(response.is_error, Some(mode == "error"));
        assert!(serde_json::to_string(&response)?.contains("receiver-ok"));
    }
    assert!(service.call_tool(call("large")).await.is_err());
    assert!(service.call_tool(call("json")).await.is_ok());
    service.cancel().await?;
    let counts = receiver.counts()?;
    assert_eq!(counts["effects"], 5);
    assert_eq!(counts["deleted"], 1);
    assert!(counts["versioned"].as_u64().unwrap() >= 7);
    assert_eq!(client.metrics().snapshot().active_bodies, 0);
    println!("RECEIVER_EFFECTS {counts}");
    println!(
        "ADAPTER_RESOURCES {}",
        serde_json::to_string(&client.metrics().snapshot())?
    );
    Ok(())
}
#[tokio::test]
async fn tls_and_auth_refusals_never_reach_tools() -> Result<(), Error> {
    let receiver = Receiver::start().await?;
    let untrusted = support::client(Default::default());
    assert!(
        config()
            .serve(untrusted.transport(receiver.url.clone(), Some("synthetic-test-token".into())))
            .await
            .is_err()
    );
    let trusted = receiver.client()?;
    assert!(
        config()
            .serve(trusted.transport(receiver.url.clone(), None))
            .await
            .is_err()
    );
    let counts = receiver.counts()?;
    assert_eq!(counts["effects"], 0);
    assert_eq!(counts["denied"], 1);
    Ok(())
}

#[tokio::test]
async fn sdk_cancellation_is_delivered_without_replaying_call() -> Result<(), Error> {
    use rmcp::{
        model::{CallToolRequest, ClientRequest},
        service::PeerRequestOptions,
    };
    use std::time::Duration;
    let receiver = Receiver::start().await?;
    let client = receiver.client()?;
    let service = config()
        .serve(client.transport(receiver.url.clone(), Some("synthetic-test-token".into())))
        .await?;
    let handle = service
        .send_request_with_option(
            ClientRequest::CallToolRequest(CallToolRequest::new(call("slow"))),
            PeerRequestOptions::with_timeout(Duration::from_millis(80)),
        )
        .await?;
    assert!(handle.await_response().await.is_err());
    wait_cancellation(&receiver).await?;
    assert!(service.call_tool(call("json")).await.is_ok());
    service.cancel().await?;
    let counts = receiver.counts()?;
    assert_eq!(counts["effects"], 2);
    assert_eq!(counts["initializations"], 1);
    assert_eq!(client.metrics().snapshot().active_bodies, 0);
    println!("CANCELLATION_EFFECTS {counts}");
    Ok(())
}

async fn wait_cancellation(receiver: &Receiver) -> Result<(), Error> {
    use std::time::Duration;
    tokio::time::timeout(Duration::from_secs(2), async {
        while receiver.counts().unwrap()["cancelled"] == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}
