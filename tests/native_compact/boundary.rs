use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_facade_methods_do_not_close_or_advance_sessions() {
    let mut f = fixture::Fixture::new();
    receiver::configure(&f);
    let up = receiver::Receiver::start(&f);
    std::fs::write(
        f.path().join("mcp.json"),
        json!({"protocol_version":"2025-11-25","allow_private_destination":true,"compact":true})
            .to_string(),
    )
    .unwrap();
    f.start(process::DAEMON).await;
    let a = f.enroll(
        "cross-facade",
        &format!("https://localhost:{}/mcp", up.port),
    );
    let t = a["token"].as_str().unwrap();
    let standard = wire::open(&f, t).await;
    let response = post(&f, t, None, wire::init()).await;
    assert_eq!(response.status(), 200);
    let compact = response.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    response.text().await.unwrap();
    post(
        &f,
        t,
        Some(&compact),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    for (session, path) in [
        (&standard, "/mcp/native/compact"),
        (&compact, "/mcp/native"),
    ] {
        for method in [
            reqwest::Method::GET,
            reqwest::Method::DELETE,
            reqwest::Method::POST,
        ] {
            let mut r = f
                .http
                .request(method.clone(), f.url(path))
                .bearer_auth(t)
                .header("accept", "application/json, text/event-stream")
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", "2025-11-25");
            if method == reqwest::Method::POST {
                r = r.json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
            }
            let r = r.send().await.unwrap();
            assert_eq!(r.status(), 404);
            assert_eq!(
                r.json::<Value>().await.unwrap()["error"]["code"],
                "session_unavailable"
            );
        }
    }
    assert_eq!(
        wire::post(
            &f,
            t,
            Some(&standard),
            json!({"jsonrpc":"2.0","id":1,"method":"ping"})
        )
        .await
        .status(),
        200
    );
    let response = rpc(
        &f,
        t,
        &compact,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 3);
    grant(&f, a["public_id"].as_str().unwrap());
    let searched = payload(call(&f, t, &compact, 2, "search", json!({"query":"read"})).await);
    assert_eq!(searched["matches"], json!([]));
    assert!(!f.path().join("effects.json").exists());
    f.stop();
    up.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standard_and_compact_share_the_same_connection_capacity() {
    let (mut f, up, a) = setup().await;
    let t = a["token"].as_str().unwrap();
    for n in 0..16 {
        if n % 2 == 0 {
            wire::open(&f, t).await;
        } else {
            open(&f, t).await;
        }
    }
    assert_eq!(post(&f, t, None, wire::init()).await.status(), 429);
    assert_eq!(wire::post(&f, t, None, wire::init()).await.status(), 429);
    assert!(!f.path().join("effects.json").exists());
    f.stop();
    up.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compact_admission_insert_and_actual_deferred_commit_failures_have_no_effect() {
    let (mut f, up, a) = setup().await;
    let t = a["token"].as_str().unwrap();
    grant(&f, a["public_id"].as_str().unwrap());
    let session = open(&f, t).await;
    rpc(
        &f,
        t,
        &session,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    let found = payload(call(&f, t, &session, 2, "search", json!({"query":"read"})).await);
    let e = &found["matches"][0];
    payload(
        call(
            &f,
            t,
            &session,
            3,
            "describe",
            json!({"handle":e["handle"]}),
        )
        .await,
    );
    let args = json!({"handle":e["handle"],"contract_digest":e["contract_digest"],"arguments":{"key":"record"}});
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(f.path().join("state.db"))
            .foreign_keys(true),
    )
    .await
    .unwrap();
    sqlx::raw_sql("CREATE TRIGGER fail_admission BEFORE INSERT ON audit WHEN NEW.event='mcp_admitted' BEGIN SELECT RAISE(ABORT,'fixture'); END;").execute(&pool).await.unwrap();
    assert_eq!(
        call(&f, t, &session, 4, "invoke", args.clone()).await["error"]["data"]["code"],
        "admission_audit_failed"
    );
    sqlx::raw_sql("DROP TRIGGER fail_admission; CREATE TABLE parent_guard(id INTEGER PRIMARY KEY); CREATE TABLE deferred_guard(id INTEGER REFERENCES parent_guard(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER INSERT ON audit WHEN NEW.event='mcp_admitted' BEGIN INSERT INTO deferred_guard VALUES(1); END;").execute(&pool).await.unwrap();
    assert_eq!(
        call(&f, t, &session, 5, "invoke", args.clone()).await["error"]["data"]["code"],
        "admission_commit_failed"
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(!f.path().join("effects.json").exists());
    sqlx::query("DROP TRIGGER fail_commit")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call(&f, t, &session, 6, "invoke", args).await["result"]["structuredContent"]["account"],
        "None"
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    pool.close().await;
    f.stop();
    up.stop();
}
async fn setup() -> (fixture::Fixture, receiver::Receiver, Value) {
    let mut f = fixture::Fixture::new();
    receiver::configure(&f);
    std::fs::write(
        f.path().join("mcp.json"),
        json!({"protocol_version":"2025-11-25","allow_private_destination":true,"compact":true})
            .to_string(),
    )
    .unwrap();
    let up = receiver::Receiver::start(&f);
    f.start(process::DAEMON).await;
    let a = f.enroll(
        "compact-boundary",
        &format!("https://localhost:{}/mcp", up.port),
    );
    (f, up, a)
}
async fn open(f: &fixture::Fixture, t: &str) -> String {
    let r = post(f, t, None, wire::init()).await;
    assert_eq!(r.status(), 200);
    let id = r.headers()["mcp-session-id"].to_str().unwrap().to_owned();
    r.text().await.unwrap();
    assert_eq!(
        post(
            f,
            t,
            Some(&id),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .await
        .status(),
        202
    );
    id
}
