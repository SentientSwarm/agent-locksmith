mod support;
use locksmith_mcp_transport::{Client, Limits};
use rmcp::ServiceExt;
use std::time::Duration;
use support::{Error, process::Receiver};

const REQUEST_TIMEOUT_MS: u64 = 2000;

async fn one_get(mode: &str) -> Result<(), Error> {
    let receiver = Receiver::start_mode(mode).await?;
    let client = bounded_client(&receiver)?;
    let service = Client::client_config()
        .serve(client.transport(receiver.url.clone(), Some("synthetic-test-token".into())))
        .await?;
    observe_get(&receiver, &client, mode).await?;
    let wait_ms = if mode == "deadline" {
        REQUEST_TIMEOUT_MS + 250
    } else {
        200
    };
    tokio::time::sleep(Duration::from_millis(wait_ms)).await;
    let counts = receiver.counts()?;
    println!("GET_RENEWAL {mode} before cancellation: {counts}");
    assert_eq!(counts["gets"], 1, "SDK renewed a failed/closed common GET");
    assert_eq!(counts["initializations"], 1);
    assert_eq!(counts["effects"], 0);
    assert_eq!(client.metrics().snapshot().active_bodies, 0);
    if mode == "deadline" {
        assert_eq!(counts["get_bodies"], 0, "receiver ended the held GET");
    }
    service.cancel().await?;
    Ok(())
}

fn bounded_client(receiver: &Receiver) -> Result<Client, Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Ok(Client::new(
        Limits {
            response_bytes: 32768,
            timeout_ms: REQUEST_TIMEOUT_MS,
            connect_timeout_ms: REQUEST_TIMEOUT_MS,
            ..Default::default()
        },
        vec![reqwest::Certificate::from_pem(
            receiver.certificate.as_bytes(),
        )?],
    )?)
}

async fn observe_get(receiver: &Receiver, client: &Client, mode: &str) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let arrived = receiver.counts()?["gets"].as_u64().unwrap() > 0;
            let active = mode != "deadline" || client.metrics().snapshot().active_bodies > 0;
            if arrived && active {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn common_get_limit_failure_cannot_renew() -> Result<(), Error> {
    one_get("oversize").await
}

#[tokio::test]
async fn common_get_retry_field_cannot_renew() -> Result<(), Error> {
    one_get("retry").await
}

#[tokio::test]
async fn common_get_deadline_cannot_renew() -> Result<(), Error> {
    one_get("deadline").await
}
