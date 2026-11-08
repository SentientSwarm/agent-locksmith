use super::{fixture::Fixture, process, wire};
use serde_json::json;

pub async fn exercise() {
    let mut f = Fixture::new();
    f.start(process::DAEMON).await;
    let a = f.enroll("caller", "https://example.com/mcp");
    let token = a["token"].as_str().unwrap();
    let id = wire::open(&f, token).await;
    let original = f.op(&["tool", "get", "native"]);
    for endpoint in [
        "not-a-url".to_owned(),
        "http://example.com/mcp".into(),
        f.url("/mcp/native"),
    ] {
        reject(&f, &endpoint);
        assert_eq!(f.op(&["tool", "get", "native"]), original);
    }
    let response = wire::post(
        &f,
        token,
        Some(&id),
        json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert!(response.text().await.unwrap().contains("result"));
    f.stop();
}
fn reject(f: &Fixture, endpoint: &str) {
    let args = [
        "tool",
        "put",
        "native",
        "--upstream",
        endpoint,
        "--auth",
        "none",
        "--egress",
        "direct",
        "--protocol",
        "mcp_streamable_http",
        "--mcp-config-file",
    ];
    let mut command = f.command(&args);
    command.arg(f.path().join("mcp.json"));
    assert!(
        !process::run(command).status.success(),
        "invalid update accepted"
    );
}
