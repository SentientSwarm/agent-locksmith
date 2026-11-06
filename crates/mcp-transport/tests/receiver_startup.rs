mod support;
use locksmith_mcp_transport::Client;
use rmcp::ServiceExt;
use support::{Error, process::Receiver};

#[tokio::test]
async fn incomplete_port_publication_is_not_receiver_readiness() -> Result<(), Error> {
    let receiver = Receiver::start_mode("startup").await?;
    let client = receiver.client()?;
    let service = Client::client_config()
        .serve(client.transport(receiver.url.clone(), Some("synthetic-test-token".into())))
        .await?;
    assert_eq!(service.list_tools(None).await?.tools.len(), 1);
    service.cancel().await?;
    assert_eq!(receiver.counts()?["effects"], 0);
    Ok(())
}
