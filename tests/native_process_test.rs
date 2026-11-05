#[path = "native_process/clients.rs"]
mod clients;
#[path = "native_process/drain.rs"]
mod drain;
#[path = "native_process/fixture.rs"]
#[allow(dead_code)] // Shared with native_preparation_process_test.
mod fixture;
#[path = "native_process/mtls.rs"]
mod mtls;
#[path = "native_process/observations.rs"]
mod observations;
#[path = "native_process/pki.rs"]
mod pki;
#[path = "explicit_binding_smoke/process.rs"]
mod process;
#[path = "native_process/receiver.rs"]
mod receiver;
#[path = "native_process/validation.rs"]
mod validation;
#[path = "native_process/wire.rs"]
mod wire;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shipping_daemon_tls_rust_lifecycle_has_no_tool_authority() {
    let mut f = fixture::Fixture::new();
    f.start(process::DAEMON).await;
    let agent = f.enroll("caller", "https://example.com/mcp");
    clients::rust(&f, agent["token"].as_str().unwrap()).await;
    clients::python(&f, agent["token"].as_str().unwrap());
    mtls::exercise(&f, &agent).await;
    wire::exercise(&mut f, &agent).await;
    f.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn process_budget_database_lock_and_held_tls_shutdown() {
    drain::exercise().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_raw_http_and_forged_methods_have_zero_receiver_arrivals() {
    let receiver = receiver::Receiver::start();
    let mut f = fixture::Fixture::new();
    f.start(process::DAEMON).await;
    let a = f.enroll(
        "caller",
        &format!("https://127.0.0.1:{}/mcp", receiver.port),
    );
    let token = a["token"].as_str().unwrap();
    let id = wire::open(&f, token).await;
    refusals(&f, &receiver, token, &id).await;
    f.stop();
    assert_eq!(receiver.count(), 0);
}

async fn refusals(f: &fixture::Fixture, receiver: &receiver::Receiver, token: &str, id: &str) {
    for method in ["tools/call", "sampling/createMessage", "forged/method"] {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"name":"secret-canary-202","arguments":{}}});
        let response = f
            .http
            .post(f.url("/api/native/mcp"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
        let response = wire::post(f, token, Some(id), body).await;
        let text = response.text().await.unwrap();
        assert!(text.contains(if method == "tools/call" {
            "tool_not_approved"
        } else {
            "method_not_found"
        }));
        assert!(!text.contains("secret-canary-202"));
        assert_eq!(receiver.count(), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_protocol_fields_never_enter_daemon_logs() {
    let mut f = fixture::Fixture::new();
    f.start(process::DAEMON).await;
    let a = f.enroll("caller", "https://example.com/mcp");
    let token = a["token"].as_str().unwrap();
    let mut body = wire::init();
    body["params"]["clientInfo"]["name"] = "secret-canary-202".into();
    let r = wire::post(&f, token, None, body).await;
    assert_eq!(r.status(), 200);
    let id = r.headers()["mcp-session-id"].to_str().unwrap().to_owned();
    let _ = r.text().await.unwrap();
    for body in [
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        serde_json::json!({"jsonrpc":"2.0","id":"private-id-202","method":"tools/call","params":{"name":"secret-canary-202","arguments":{"secret":"secret-canary-202"}}}),
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":999,"reason":"secret-canary-202"}}),
    ] {
        let r = wire::post(&f, token, Some(&id), body).await;
        assert!(r.status().is_success());
        let _ = r.text().await.unwrap();
    }
    f.stop();
    observations::audit(f.path()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_native_operator_updates_preserve_live_authority() {
    validation::exercise().await;
}
