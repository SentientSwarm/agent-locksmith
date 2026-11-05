use super::{fixture::Fixture, process};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, ClientRequest},
};

pub async fn rust(f: &Fixture, token: &str) {
    let root = reqwest_mcp::Certificate::from_pem(f.pki.ca.as_bytes()).unwrap();
    let client = locksmith_mcp_transport::Client::new(Default::default(), vec![root]).unwrap();
    let service = locksmith_mcp_transport::Client::client_config()
        .serve(client.transport(f.url("/mcp/native"), Some(token.into())))
        .await
        .unwrap();
    assert!(service.list_tools(None).await.unwrap().tools.is_empty());
    service
        .send_request(ClientRequest::PingRequest(Default::default()))
        .await
        .unwrap();
    let call: CallToolRequestParams =
        serde_json::from_value(serde_json::json!({"name":"unapproved","arguments":{}})).unwrap();
    let error = service.call_tool(call).await.unwrap_err();
    assert!(format!("{error:?}").contains("tool_not_approved"));
    service.cancel().await.unwrap();
    assert_eq!(client.metrics().snapshot().active_bodies, 0);
}
pub fn python(f: &Fixture, token: &str) {
    let Ok(binary) = std::env::var("LOCKSMITH_NATIVE_PYTHON") else {
        println!("Python consumer skipped: LOCKSMITH_NATIVE_PYTHON not set");
        return;
    };
    let mut c = process::command(&binary);
    c.arg(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_process/python_client.py"
    ));
    c.env("PROOF_URL", f.url("/mcp/native"))
        .env("PROOF_CA", &f.pki.ca)
        .env("PROOF_AGENT_HEADER", format!("Bearer {token}"));
    let out = process::run(c);
    assert!(
        out.status.success(),
        "Python consumer failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    println!("{}", String::from_utf8_lossy(&out.stdout));
}
