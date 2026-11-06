mod support;
use rmcp::{ServiceExt, transport::streamable_http_client::StreamableHttpClient};
use std::{collections::HashMap, sync::Arc, time::Duration};
use support::{process::Receiver, *};

#[tokio::test]
async fn cloned_direct_clients_share_one_atomic_get_attempt() -> Result<(), Error> {
    let s = Server::start(Reply::body("text/event-stream", b":x\n\n".to_vec())).await;
    let c = client(limits(1024));
    let clone = c.clone();
    let (a, b) = tokio::join!(get(&c, &s), get(&clone, &s));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    drop((a, b));
    assert!(get(&c, &s).await.is_err());
    assert_eq!(s.hits(), 1);
    assert_eq!(c.metrics().snapshot().active_bodies, 0);
    assert!(get(&client(limits(1024)), &s).await.is_ok());
    assert_eq!(s.hits(), 2);
    Ok(())
}

async fn get(c: &locksmith_mcp_transport::Client, s: &Server) -> Result<(), Error> {
    drop(
        c.get_stream(Arc::from(s.url.as_str()), None, None, None, HashMap::new())
            .await?,
    );
    Ok(())
}

#[tokio::test]
async fn deliberate_new_transport_has_a_fresh_get_budget() -> Result<(), Error> {
    let receiver = Receiver::start().await?;
    let client = receiver.client()?;
    for count in 1..=2 {
        let service = locksmith_mcp_transport::Client::client_config()
            .serve(client.transport(receiver.url.clone(), Some("synthetic-test-token".into())))
            .await?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while receiver.counts().unwrap()["gets"] != count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        service.cancel().await?;
    }
    assert_eq!(receiver.counts()?["initializations"], 2);
    assert_eq!(receiver.counts()?["gets"], 2);
    assert_eq!(client.metrics().snapshot().active_bodies, 0);
    Ok(())
}
