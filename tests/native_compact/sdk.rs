use super::{fixture::Fixture, process, receiver, support as s};
use rmcp::{ServiceExt, model::CallToolRequestParams};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_sdks_standard_compact_x_shared_x_y_none_and_all_protected() {
    let mut f = Fixture::new();
    receiver::configure(&f);
    s::manifest(&f);
    std::fs::write(
        f.path().join("mcp.json"),
        json!({"protocol_version":"2025-11-25","allow_private_destination":true,"compact":true})
            .to_string(),
    )
    .unwrap();
    let up = receiver::Receiver::start(&f);
    f.start_with_key(
        process::DAEMON,
        Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
    )
    .await;
    let url = format!("https://localhost:{}/mcp", up.port);
    let a = f.enroll("compact-sdk", &url);
    let b = f.enroll("shared-sdk", &url);
    let none = f.enroll("none-sdk", &url);
    let id = a["public_id"].as_str().unwrap();
    let reference = s::stored(&f, id, "fixture-account-x");
    f.op(&[
        "agent",
        "set-credential",
        b["public_id"].as_str().unwrap(),
        "native",
        "--stored-bearer-ref",
        &reference,
    ]);
    exercise(&f, &a, "X", false).await;
    s::stored(&f, id, "fixture-account-y");
    exercise(&f, &b, "X", false).await;
    exercise(&f, &a, "Y", false).await;
    exercise(&f, &none, "None", true).await;
    let effects = s::effects(&f);
    assert_eq!(effects.len(), 16);
    let mut ids = std::collections::HashSet::new();
    for (n, e) in effects.iter().enumerate() {
        assert_eq!(e["account"], ["X", "X", "Y", "None"][n / 4]);
        assert_eq!(e["arguments"], json!({"workspace":"fixed","key":"record"}));
        assert_eq!(e["committed"], n + 1);
        assert!(ids.insert(e["admission"]["admission_id"].as_str().unwrap().to_owned()));
        assert_eq!(e["admission"]["tool_name"], "read_record");
    }
    f.stop();
    up.stop();
}
async fn exercise(f: &Fixture, a: &Value, account: &str, all: bool) {
    let id = a["public_id"].as_str().unwrap();
    let context = if all {
        json!({"workspace":"fixed","key":"record"})
    } else {
        json!({"workspace":"fixed"})
    };
    let reviewed = s::review(f, id, context, "read_record");
    s::grant(f, id, &reviewed);
    let token = a["token"].as_str().unwrap();
    for compact in [false, true] {
        rust(f, token, account, compact, all).await;
        python(f, token, account, compact, all);
    }
}
async fn rust(f: &Fixture, token: &str, account: &str, compact: bool, all: bool) {
    let root = reqwest_mcp::Certificate::from_pem(f.pki.ca.as_bytes()).unwrap();
    let client = locksmith_mcp_transport::Client::new(Default::default(), vec![root]).unwrap();
    let path = if compact {
        "/mcp/native/compact"
    } else {
        "/mcp/native"
    };
    let service = locksmith_mcp_transport::Client::client_config()
        .serve(client.transport(f.url(path), Some(token.into())))
        .await
        .unwrap();
    let listed = service.list_tools(None).await.unwrap();
    let (schema, handle, digest) = if compact {
        assert_eq!(
            listed
                .tools
                .iter()
                .map(|t| t.name.as_ref())
                .collect::<Vec<_>>(),
            ["search", "describe", "invoke"]
        );
        let r = service
            .call_tool(params("search", json!({"query":"read"})))
            .await
            .unwrap();
        let search = payload(serde_json::to_value(r).unwrap());
        let e = &search["matches"][0];
        let r = service
            .call_tool(params("describe", json!({"handle":e["handle"]})))
            .await
            .unwrap();
        let described = payload(serde_json::to_value(r).unwrap());
        assert_eq!(described["contract_digest"], e["contract_digest"]);
        (
            described["input_schema"].clone(),
            e["handle"].clone(),
            e["contract_digest"].clone(),
        )
    } else {
        assert_eq!(listed.tools.len(), 1);
        (
            serde_json::to_value(&listed.tools[0].input_schema).unwrap(),
            Value::Null,
            Value::Null,
        )
    };
    assert!(schema["properties"].get("workspace").is_none());
    assert_eq!(schema["properties"].get("key").is_none(), all);
    let args = if all {
        json!({})
    } else {
        json!({"key":"record"})
    };
    let call = if compact {
        params(
            "invoke",
            json!({"handle":handle,"contract_digest":digest,"arguments":args}),
        )
    } else {
        params("read_record", args)
    };
    let result = serde_json::to_value(service.call_tool(call).await.unwrap()).unwrap();
    assert_eq!(result["content"][0]["text"], account);
    assert_ne!(result["isError"], true);
    service.cancel().await.unwrap();
    assert_eq!(client.metrics().snapshot().active_bodies, 0);
}
fn params(name: &str, args: Value) -> CallToolRequestParams {
    serde_json::from_value(json!({"name":name,"arguments":args})).unwrap()
}
fn payload(v: Value) -> Value {
    serde_json::from_str(v["content"][0]["text"].as_str().unwrap()).unwrap()
}
fn python(f: &Fixture, token: &str, account: &str, compact: bool, all: bool) {
    let Ok(binary) = std::env::var("LOCKSMITH_NATIVE_PYTHON") else {
        println!("Python compact SDK NOT RUN: set LOCKSMITH_NATIVE_PYTHON");
        return;
    };
    let mut c = process::command(&binary);
    c.arg(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_compact/python_client.py"
    ))
    .env(
        "PROOF_URL",
        f.url(if compact {
            "/mcp/native/compact"
        } else {
            "/mcp/native"
        }),
    )
    .env("PROOF_CA", &f.pki.ca)
    .env("PROOF_AGENT_HEADER", format!("Bearer {token}"))
    .env("PROOF_COMPACT", compact.to_string())
    .env("PROOF_ALL", all.to_string())
    .env("PROOF_ACCOUNT", account);
    let output = process::run(c);
    assert!(
        output.status.success(),
        "Python compact SDK: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
