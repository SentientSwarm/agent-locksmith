mod support;
use locksmith_mcp_transport::Limits;
use std::time::Duration;
use support::*;

#[tokio::test]
async fn json_depth_units_and_schema_data_are_checked() -> Result<(), Error> {
    let deep = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"schema":{}0{}}}}}"#,
        "[".repeat(40),
        "]".repeat(40)
    );
    let wide = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"schema":[{}]}}}}"#,
        vec!["0"; 500].join(",")
    );
    for (body, diagnostic) in [(deep, "json_depth"), (wide, "json_units")] {
        let c = client(Limits {
            json_units: 100,
            ..limits(8192)
        });
        let s = Server::start(Reply::body("application/json", body.into_bytes())).await;
        assert!(
            post(&c, &s)
                .await
                .unwrap_err()
                .to_string()
                .contains(diagnostic)
        );
    }
    Ok(())
}
#[tokio::test]
async fn chunk_budget_and_early_close_are_observable() -> Result<(), Error> {
    let mut reply = Reply::body("application/json", json(2048));
    reply.hold = true;
    let server = Server::start(reply).await;
    let c = client(Limits {
        chunk_bytes: 16,
        ..limits(4096)
    });
    assert!(
        post(&c, &server)
            .await
            .unwrap_err()
            .to_string()
            .contains("chunk_bytes")
    );
    server.wait_closed().await;
    let snapshot = c.metrics().snapshot();
    assert!(snapshot.received > 16);
    assert_eq!(snapshot.admitted, 0);
    assert_eq!(snapshot.active_bodies, 0);
    println!("{}", serde_json::to_string(&snapshot)?);
    Ok(())
}
#[tokio::test]
async fn chunk_count_and_absolute_deadline_do_not_reset() -> Result<(), Error> {
    for (chunks, timeout_ms, diagnostic) in [(2, 1000, "chunks"), (100, 35, "deadline")] {
        let mut reply = Reply::body("application/json", Vec::new());
        reply.parts = vec![b" ".to_vec(); 20];
        reply.delay = Duration::from_millis(15);
        let server = Server::start(reply).await;
        let c = client(Limits {
            chunks,
            timeout_ms,
            connect_timeout_ms: 20,
            ..limits(256)
        });
        assert!(
            post(&c, &server)
                .await
                .unwrap_err()
                .to_string()
                .contains(diagnostic)
        );
        assert_eq!(c.metrics().snapshot().active_bodies, 0);
    }
    Ok(())
}
#[tokio::test]
async fn dropped_json_future_and_sse_stream_release_bodies() -> Result<(), Error> {
    let mut reply = Reply::body("application/json", b"{".to_vec());
    reply.hold = true;
    let server = Server::start(reply).await;
    let c = client(limits(1024));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), post(&c, &server))
            .await
            .is_err()
    );
    server.wait_closed().await;
    assert_eq!(c.metrics().snapshot().active_bodies, 0);
    let mut reply = Reply::body("text/event-stream", Vec::new());
    reply.hold = true;
    let server = Server::start(reply).await;
    drop(post(&c, &server).await?);
    server.wait_closed().await;
    assert_eq!(c.metrics().snapshot().active_bodies, 0);
    let server = Server::start(Reply::body("application/json", json(128))).await;
    assert!(post(&c, &server).await.is_ok());
    Ok(())
}
#[test]
fn invalid_configuration_refuses_unlimited_and_excessive_values() {
    for limits in [
        Limits {
            response_bytes: 0,
            ..Limits::default()
        },
        Limits {
            json_depth: 65,
            ..Limits::default()
        },
        Limits {
            timeout_ms: 0,
            ..Limits::default()
        },
    ] {
        assert!(locksmith_mcp_transport::Client::new(limits, vec![]).is_err());
    }
}

#[tokio::test]
async fn cumulative_body_limit_refuses_before_unbounded_tail() -> Result<(), Error> {
    let mut reply = Reply::body("application/json", json(2048));
    reply.hold = true;
    let s = Server::start(reply).await;
    let c = client(limits(256));
    assert!(
        post(&c, &s)
            .await
            .unwrap_err()
            .to_string()
            .contains("response_bytes")
    );
    s.wait_closed().await;
    assert_eq!(c.metrics().snapshot().admitted, 0);
    assert_eq!(c.metrics().snapshot().active_bodies, 0);
    Ok(())
}
#[tokio::test]
async fn valid_json_requires_bounded_eof_not_early_success() -> Result<(), Error> {
    let mut reply = Reply::body("application/json", json(128));
    reply.hold = true;
    let s = Server::start(reply).await;
    let c = client(Limits {
        timeout_ms: 50,
        connect_timeout_ms: 30,
        ..limits(256)
    });
    assert!(
        post(&c, &s)
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline")
    );
    s.wait_closed().await;
    assert_eq!(c.metrics().snapshot().active_bodies, 0);
    Ok(())
}
