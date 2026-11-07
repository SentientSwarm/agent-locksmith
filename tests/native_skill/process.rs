use super::{snapshot::authority, support as s};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_guidance_gets_are_local_then_discovered_http_and_native_calls_work() {
    let (mut f, receiver, a) = s::setup().await;
    let http = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/check"))
        .respond_with(ResponseTemplate::new(200).set_body_string("HTTP-None"))
        .mount(&http)
        .await;
    let id = a["public_id"].as_str().unwrap();
    let token = a["token"].as_str().unwrap();
    s::stored(&f, id, "fixture-account-x");
    f.op(&[
        "tool",
        "put",
        "accounts",
        "--upstream",
        &http.uri(),
        "--auth",
        "none",
        "--egress",
        "direct",
        "--metadata-file",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/http-service-reference.json"
        ),
    ]);
    f.op(&["agent", "modify", id, "--allowlist", "native,accounts"]);
    f.op(&["agent", "set-credential", id, "accounts", "--no-auth"]);
    let review = s::review(&f, id, json!({"workspace":"guided-scope"}), "read_record");
    s::grant(&f, id, &review);
    let before = authority(&f).await;
    let counts = std::fs::read(f.path().join("counts.json")).unwrap();
    let generic = f.http.get(f.url("/skill")).send().await.unwrap();
    assert_eq!(generic.headers()["cache-control"], "public, max-age=86400");
    let generic = generic.text().await.unwrap();
    assert!(!generic.contains(id) && !generic.contains("/mcp/native"));
    let bad = f
        .http
        .get(f.url("/skill"))
        .bearer_auth("synthetic-invalid")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401);
    let skill = f
        .http
        .get(f.url("/skill"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        skill.headers()["cache-control"],
        "private, no-cache, no-store"
    );
    assert_eq!(
        skill.headers()["content-type"],
        "text/markdown; charset=utf-8"
    );
    let skill = skill.text().await.unwrap();
    let discovery: Value = f
        .http
        .get(f.url("/tools"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = discovery["tools"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let personal = skill.split("## Personalized for").nth(1).unwrap();
    for entry in entries {
        assert!(personal.contains(entry["path"].as_str().unwrap()));
    }
    assert!(
        personal.contains("Call a native MCP tool") && personal.contains("Call an HTTP connection")
    );
    assert_eq!(
        authority(&f).await,
        before,
        "guidance must not change authority/custody/activation"
    );
    assert_eq!(std::fs::read(f.path().join("counts.json")).unwrap(), counts);
    assert!(http.received_requests().await.unwrap().is_empty());
    assert!(s::effects(&f).is_empty());
    for private in [
        "fixture-account-x",
        "guided-scope",
        "secret_ref",
        &format!("localhost:{}", receiver.port),
    ] {
        assert!(!skill.contains(private), "private setup data in guidance");
    }

    let entry = entries.iter().find(|e| e["type"] == "api").unwrap();
    let operation = &entry["http_service"]["operations"][0];
    let route = format!(
        "{}{}",
        entry["path"].as_str().unwrap(),
        operation["path"].as_str().unwrap()
    );
    let response = f
        .http
        .request(
            operation["method"].as_str().unwrap().parse().unwrap(),
            f.url(&route),
        )
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "HTTP-None");

    let native = entries.iter().find(|e| e["type"] == "mcp").unwrap();
    // The reused native wire helper targets exactly the discovered endpoint.
    assert_eq!(native["path"], "/mcp/native");
    let session = s::open(&f, &a).await;
    let list = s::rpc(&f, &a, &session, 2, "tools/list", json!({})).await;
    let tool = &list["result"]["tools"][0];
    assert_eq!(tool["inputSchema"]["required"], json!(["key"]));
    assert!(tool["inputSchema"]["properties"].get("workspace").is_none());
    let result = s::rpc(
        &f,
        &a,
        &session,
        3,
        "tools/call",
        json!({"name":tool["name"],"arguments":{"key":"guided-record"}}),
    )
    .await;
    assert_eq!(result["result"]["content"][0]["text"], "X");
    let effect = s::effects(&f);
    assert_eq!(effect.len(), 1);
    assert_eq!(
        effect[0]["arguments"],
        json!({"key":"guided-record","workspace":"guided-scope"})
    );
    assert_eq!(
        effect[0]["admission"]["contract_digest"],
        review["contract_digest"]
    );
    assert_eq!(effect[0]["committed"], 1);
    let wrong = f
        .http
        .get(f.url("/api/native/check"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert!(!wrong.status().is_success());
    assert_eq!(s::effects(&f).len(), 1);
    assert_eq!(http.received_requests().await.unwrap().len(), 1);
    println!(
        "guidance reads: 0 upstream POST/HTTP/TOOL; useful calls: HTTP1/native1; fixed context + committed admission; wrong route0"
    );
    f.stop();
    receiver.stop();
}
