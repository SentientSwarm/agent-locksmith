use super::*;
pub(super) fn tools() -> Value {
    let mut value = json!({"tools":[
        {"name":"read_record","_meta":{"invented":["https://invalid.example/inert"]},"inputSchema":{"type":"object","properties":{"key":{"type":"string","enum":(0..45).map(|i|format!("choice-{i}")).collect::<Vec<_>>(),"default":"choice-0"},"flag":{"type":"boolean","default":false}},"additionalProperties":false}},
        {"name":"empty_record","inputSchema":{"type":"object","properties":{}}},
        {"name":"other_record","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"last_record","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}
    ]});
    for i in 0..37 {
        value["tools"].as_array_mut().unwrap().push(omitted(i));
    }
    value
}
pub(super) fn omitted(n: usize) -> Value {
    json!({"name":format!("omitted_{n}"),"inputSchema":{"anyOf":[{"type":"string"}]}})
}
pub(super) fn config(f: &fixture::Fixture, policy: Option<&str>) {
    let mut v =
        json!({"protocol_version":"2025-11-25","allow_private_destination":true,"compact":true});
    if let Some(p) = policy {
        v["contract_policy"] = p.into();
        v["selected_tools"] = json!(["read_record", "empty_record", "other_record", "last_record"]);
    }
    write(f, "mcp.json", v);
}
pub(super) fn write(f: &fixture::Fixture, name: &str, value: Value) {
    std::fs::write(f.path().join(name), value.to_string()).unwrap();
}
pub(super) fn put(f: &fixture::Fixture, port: u16) {
    f.op(&[
        "tool",
        "put",
        "native",
        "--upstream",
        &format!("https://localhost:{port}/mcp"),
        "--auth",
        "none",
        "--egress",
        "direct",
        "--protocol",
        "mcp_streamable_http",
        "--mcp-config-file",
        f.path().join("mcp.json").to_str().unwrap(),
    ]);
}
pub(super) fn effects(f: &fixture::Fixture) -> Vec<Value> {
    serde_json::from_slice(&std::fs::read(f.path().join("effects.json")).unwrap()).unwrap()
}
pub(super) async fn parse(r: reqwest::Response) -> Value {
    let body = r.text().await.unwrap();
    serde_json::from_str(
        body.lines()
            .find_map(|l| l.strip_prefix("data: "))
            .unwrap_or(&body),
    )
    .unwrap()
}
