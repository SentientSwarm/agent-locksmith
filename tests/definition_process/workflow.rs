use super::{fixture::Fixture, invalid, process, receiver::Receiver, support, wire};
use serde_json::{Value, json};

pub async fn exercise() {
    let receiver = Receiver::start();
    let mut f = Fixture::new();
    f.start(process::DAEMON).await;
    let a = f.enroll("caller", "https://example.com/mcp");
    let before = support::authority(&f).await;
    let endpoint = format!("https://127.0.0.1:{}/mcp", receiver.port);
    let instance = author(&f, &endpoint);
    invalid::exercise(&f, a["token"].as_str().unwrap()).await;
    assert_eq!(support::authority(&f).await, before);
    denied(&f, a["token"].as_str().unwrap()).await;
    manual(&f, a["token"].as_str().unwrap()).await;
    f.stop();
    f.start(process::DAEMON).await;
    assert_eq!(f.op(&["tool", "get", "customer"]), instance);
    f.op(&["tool", "delete", "customer"]);
    support::create(&f, &endpoint);
    assert_eq!(support::authority(&f).await, before);
    f.stop();
    assert_eq!(receiver.count(), 0);
    assert!(
        !std::fs::read_to_string(f.path().join("daemon.log"))
            .unwrap()
            .contains("definition-secret-canary")
    );
    println!(
        "CLI/API import/get/pin/repeat/refusals/restart/delete-recreate pass; authority unchanged; receiver TCP connections=0"
    );
}
fn inspect(instance: &Value, definition: &Value) {
    assert_eq!(instance["disabled"], true);
    assert_eq!(instance["activation"], "disabled");
    assert_eq!(instance["authoring_only"], true);
    assert_eq!(instance["provider_readiness"], "unverified");
    assert_eq!(instance["credential_readiness"], "not_checked");
    assert_eq!(
        instance["mcp"]["definition"]["digest"],
        definition["digest"]
    );
}
async fn denied(f: &Fixture, token: &str) {
    for path in ["/mcp/customer", "/api/customer/mcp"] {
        let r = f
            .http
            .post(f.url(path))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&wire::init())
            .send()
            .await
            .unwrap();
        assert!(
            matches!(r.status().as_u16(), 403 | 404),
            "{path}: {}",
            r.status()
        );
    }
    let list: Value = f
        .http
        .get(f.url("/tools"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!list.to_string().contains("customer"));
}
async fn manual(f: &Fixture, token: &str) {
    f.op(&[
        "tool",
        "put",
        "manual-http",
        "--upstream",
        "https://example.com",
        "--auth",
        "none",
    ]);
    assert_eq!(f.op(&["tool", "get", "manual-http"])["disabled"], false);
    let id = wire::open(f, token).await;
    let r = wire::post(
        f,
        token,
        Some(&id),
        json!({"jsonrpc":"2.0","id":17,"method":"ping"}),
    )
    .await;
    assert_eq!(r.status(), 200);
    assert!(r.text().await.unwrap().contains("result"));
}

fn author(f: &Fixture, endpoint: &str) -> Value {
    let definition = support::import(f, 1);
    assert_eq!(support::import(f, 1), definition);
    assert_eq!(
        f.op(&["integration", "get", "local.customer", "--revision", "1"]),
        definition
    );
    let instance = support::create(f, endpoint);
    inspect(&instance, &definition);
    support::import(f, 2);
    assert_eq!(f.op(&["tool", "get", "customer"]), instance);
    instance
}
