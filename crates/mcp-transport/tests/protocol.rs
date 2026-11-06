mod support;
use rmcp::transport::streamable_http_client::{StreamableHttpClient, StreamableHttpError};
use std::{collections::HashMap, sync::Arc, time::Duration};
use support::*;

#[tokio::test]
async fn redirects_never_reach_a_second_receiver() -> Result<(), Error> {
    let destination = Server::start(Reply::body("application/json", json(128))).await;
    for status in [301, 302, 303, 307, 308] {
        let mut reply =
            Reply::body("application/json", Vec::new()).header("Location", &destination.url);
        reply.head = reply.head.replace("200 OK", &format!("{status} Redirect"));
        let source = Server::start(reply).await;
        let c = client(limits(512));
        assert!(post(&c, &source).await.is_err());
        assert_eq!(source.hits(), 1);
    }
    assert_eq!(destination.hits(), 0);
    Ok(())
}
#[tokio::test]
async fn auth_challenge_scope_is_preserved() -> Result<(), Error> {
    for status in [401, 403] {
        let mut reply = Reply::body("application/json", Vec::new())
            .header("WWW-Authenticate", "Bearer scope=\"read:user read:team\"");
        reply.head = reply.head.replace("200 OK", &format!("{status} Denied"));
        let error = post(&client(limits(512)), &Server::start(reply).await)
            .await
            .unwrap_err();
        match error {
            StreamableHttpError::AuthRequired(error) => {
                assert!(error.www_authenticate_header.contains("scope="))
            }
            StreamableHttpError::InsufficientScope(error) => {
                assert_eq!(error.required_scope.as_deref(), Some("read:user read:team"))
            }
            _ => panic!("challenge lost"),
        }
    }
    Ok(())
}
#[tokio::test]
async fn expired_session_is_preserved_without_retry() -> Result<(), Error> {
    let mut reply = Reply::body("application/json", Vec::new());
    reply.head = reply.head.replace("200 OK", "404 Gone");
    let s = Server::start(reply).await;
    let error = client(limits(512))
        .post_message(
            Arc::from(s.url.as_str()),
            ping(),
            Some("old".into()),
            None,
            HashMap::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, StreamableHttpError::SessionExpired));
    assert_eq!(s.hits(), 1);
    Ok(())
}
#[tokio::test]
async fn control_delete_and_bad_media_drop_without_collecting() -> Result<(), Error> {
    let c = client(limits(512));
    for status in [202, 204] {
        let mut reply = Reply::body("application/json", vec![b'x'; 1024]);
        reply.head = reply.head.replace("200 OK", &format!("{status} Accepted"));
        let s = Server::start(reply).await;
        assert!(post(&c, &s).await.is_ok());
    }
    let s = Server::start(Reply::body("text/plain", vec![b'x'; 2048])).await;
    c.delete_session(
        Arc::from(s.url.as_str()),
        "session".into(),
        None,
        HashMap::new(),
    )
    .await?;
    assert_eq!(c.metrics().snapshot().received, 0);
    let error = post(
        &c,
        &Server::start(Reply::body("text/html", b"CANARY".to_vec())).await,
    )
    .await
    .unwrap_err();
    assert!(!format!("{error:?}").contains("CANARY"));
    Ok(())
}
#[tokio::test]
async fn sdk_event_override_can_only_tighten_limits() -> Result<(), Error> {
    let event = format!("data: {}\n\n", String::from_utf8(json(128))?).into_bytes();
    for (own, sdk) in [(32, 65536), (65536, 32)] {
        let c = client(locksmith_mcp_transport::Limits {
            event_bytes: own,
            ..limits(65536)
        });
        let s = Server::start(Reply::body("text/event-stream", event.clone())).await;
        let response = c
            .post_message_with_max_sse_event_size(
                Arc::from(s.url.as_str()),
                ping(),
                None,
                None,
                HashMap::new(),
                sdk,
            )
            .await?;
        assert!(drain(response).await.is_err());
        assert_get_cap(&c, &s, sdk).await?;
    }
    Ok(())
}
#[tokio::test]
async fn header_deadline_is_not_body_only() -> Result<(), Error> {
    let c = client(locksmith_mcp_transport::Limits {
        timeout_ms: 50,
        connect_timeout_ms: 30,
        ..limits(512)
    });
    let mut reply = Reply::body("application/json", json(128));
    reply.head_delay = Duration::from_millis(150);
    let s = Server::start(reply).await;
    assert!(
        post(&c, &s)
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline")
    );
    Ok(())
}
#[tokio::test]
async fn sse_deadline_closes_and_allows_recovery() -> Result<(), Error> {
    let c = client(locksmith_mcp_transport::Limits {
        timeout_ms: 50,
        connect_timeout_ms: 30,
        ..limits(512)
    });
    let mut reply = Reply::body("text/event-stream", Vec::new());
    reply.hold = true;
    let s = Server::start(reply).await;
    assert!(
        drain(post(&c, &s).await?)
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline")
    );
    s.wait_closed().await;
    assert!(
        post(
            &c,
            &Server::start(Reply::body("application/json", json(128))).await
        )
        .await
        .is_ok()
    );
    assert_eq!(c.metrics().snapshot().active_bodies, 0);
    Ok(())
}

async fn assert_get_cap(
    c: &locksmith_mcp_transport::Client,
    s: &Server,
    sdk: usize,
) -> Result<(), Error> {
    let mut stream = c
        .get_stream_with_max_sse_event_size(
            Arc::from(s.url.as_str()),
            None,
            None,
            None,
            HashMap::new(),
            sdk,
        )
        .await?;
    use futures_util::StreamExt;
    assert!(stream.next().await.unwrap().is_err());
    Ok(())
}
