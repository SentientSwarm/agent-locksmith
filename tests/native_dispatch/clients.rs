use super::{calls, discovery, fixture::Fixture, process, receiver};
use rmcp::{ServiceExt, model::CallToolRequestParams};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standard_rust_and_python_clients_complete_reviewed_calls() {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let receiver = receiver::Receiver::start(&f);
    f.start(process::DAEMON).await;
    let a = f.enroll(
        "sdk-caller",
        &format!("https://localhost:{}/mcp", receiver.port),
    );
    discovery::grant(&f, a["public_id"].as_str().unwrap());
    rust(&f, a["token"].as_str().unwrap()).await;
    assert_eq!(calls::effects(&f).len(), 1);
    python(&f, a["token"].as_str().unwrap());
    f.stop();
    receiver.stop();
}
async fn rust(f: &Fixture, token: &str) {
    let root = reqwest_mcp::Certificate::from_pem(f.pki.ca.as_bytes()).unwrap();
    let client = locksmith_mcp_transport::Client::new(Default::default(), vec![root]).unwrap();
    let service = locksmith_mcp_transport::Client::client_config()
        .serve(client.transport(f.url("/mcp/native"), Some(token.into())))
        .await
        .unwrap();
    let tools = service.list_tools(None).await.unwrap();
    assert_eq!(tools.tools.len(), 1);
    assert_eq!(tools.tools[0].name, "read_record");
    let call: CallToolRequestParams =
        serde_json::from_value(json!({"name":"read_record","arguments":{"key":"rust-record"}}))
            .unwrap();
    let result = service.call_tool(call).await.unwrap();
    assert_eq!(result.structured_content, Some(json!({"account":"None"})));
    assert_ne!(result.is_error, Some(true));
    service.cancel().await.unwrap();
    assert_eq!(client.metrics().snapshot().active_bodies, 0);
}

fn python(f: &Fixture, token: &str) {
    if let Ok(binary) = std::env::var("LOCKSMITH_NATIVE_PYTHON") {
        let mut c = process::command(&binary);
        c.arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/native_dispatch/python_client.py"
        ))
        .env("PROOF_URL", f.url("/mcp/native"))
        .env("PROOF_CA", &f.pki.ca)
        .env("PROOF_AGENT_HEADER", format!("Bearer {}", token));
        let output = process::run(c);
        assert!(
            output.status.success(),
            "Python SDK: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(calls::effects(f).len(), 2);
        println!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("Python SDK NOT RUN: set LOCKSMITH_NATIVE_PYTHON");
    }
}
