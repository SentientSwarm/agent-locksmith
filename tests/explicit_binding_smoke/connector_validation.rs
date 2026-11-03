//! Operator validation must reject before mutating a working connection.
use super::{docs, fixture::Fixture, process, setup, upstream};
use serde_json::{Value, json};

pub async fn exercise() {
    let receiver = upstream::Receiver::start().await;
    let mut f = Fixture::new(&receiver.server.uri());
    f.start().await;
    let agents = setup::enroll(&f).await;
    let a = &agents[0];
    upstream::allowed(&f, &receiver, &a.token, "accounts/check", "X").await;
    let before = snapshot(&f, &a.id);
    let arrivals = receiver.snapshot().await;
    reject_destinations(&f);
    reject_declarations(&f, &a.id).await;
    assert_eq!(
        snapshot(&f, &a.id),
        before,
        "rejected writes changed authority"
    );
    assert_eq!(receiver.snapshot().await, arrivals);
    upstream::allowed(&f, &receiver, &a.token, "accounts/check", "X").await;
    println!(
        "AGENT-185 invalid destination/mode/narrow grant rejected; saved connection, grants and selection unchanged; no validation dispatch; original account X still works"
    );
    f.cleanup();
}

fn snapshot(f: &Fixture, agent: &str) -> Vec<Value> {
    let guide = include_str!("../../docs/user/operator/connector-onboarding.md");
    let mut command = docs::fixture(f, guide, "connector-inspect");
    command
        .env("REGISTRATION", "accounts")
        .env("AGENT_ID", agent);
    let output = process::run(command);
    assert!(output.status.success());
    serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn reject_destinations(f: &Fixture) {
    for upstream in [
        "not-a-url",
        "ftp://example.invalid",
        "ws://example.invalid",
        "https://user:synthetic-private@example.invalid",
        "https://example.invalid?key=hidden",
        "https://example.invalid#fragment",
        "https:///",
        "http:///example.invalid",
    ] {
        reject_destination(f, "accounts", upstream);
    }
    reject_destination(f, "invalid-new", "not-a-url");
    let absent = process::run(f.cli(&["tool", "get", "invalid-new"]));
    assert_eq!(absent.status.code(), Some(4));
}

fn reject_destination(f: &Fixture, name: &str, upstream: &str) {
    let output = process::run(f.cli(&[
        "tool",
        "put",
        name,
        "--upstream",
        upstream,
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
    ]));
    assert!(
        !output.status.success(),
        "invalid destination accepted: {upstream}"
    );
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("invalid_upstream"));
    assert!(!error.contains("synthetic-private") && !error.contains("hidden"));
}

async fn reject_declarations(f: &Fixture, agent: &str) {
    for (key, value) in [
        ("egress", json!("websocket")),
        ("mode", json!("websocket")),
        ("methods", json!(["GET"])),
        ("auth", json!({"kind":"executable"})),
    ] {
        let mut body = json!({"upstream":f.upstream,"auth":{"kind":"none"}});
        body[key] = value;
        rejected(f, "PUT", "/admin/operator/tools/accounts", body).await;
    }
    rejected(
        f,
        "PATCH",
        &format!("/admin/operator/agents/{agent}"),
        json!({"allowlist":["accounts"],"methods":["GET"]}),
    )
    .await;
}

async fn rejected(f: &Fixture, method: &str, path: &str, body: Value) {
    let client = agent_locksmith::admin::uds_client::UdsClient::new(&f.socket);
    let (status, _) = client
        .request(
            method,
            path,
            &[
                ("authorization", &format!("Bearer {}", f.operator)),
                ("content-type", "application/json"),
            ],
            Some(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .unwrap();
    assert!(
        (400..500).contains(&status),
        "unsupported declaration accepted"
    );
}
