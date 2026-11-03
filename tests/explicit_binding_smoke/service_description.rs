//! Scripted builder proof, separate from independent discovery-only QA construction.
use super::{docs, fixture::Fixture, process, setup, upstream};
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};
#[path = "service_discovery.rs"]
mod consumer;
#[path = "service_description_refusals.rs"]
mod refusals;

pub async fn exercise() {
    let reference = upstream::Receiver::start().await;
    let customer = customer().await;
    let mut f = Fixture::new(&reference.server.uri());
    f.start().await;
    let agents = setup::enroll(&f).await;
    let before = authority(&f, &agents[0].id);
    publish(&f, &customer.uri());
    assert_eq!(authority(&f, &agents[0].id), before);
    refusals::exercise(&f, &agents[0].id);
    grant_customer(&f, &agents[0].id);
    consumer::verify_scoping(&f, &agents).await;
    calls(&f, &reference, &customer, &agents).await;
    println!("AGENT-186 typed discovery and metadata authority checks passed");
    f.cleanup();
}

async fn calls(
    f: &Fixture,
    reference: &upstream::Receiver,
    customer: &MockServer,
    agents: &[setup::Agent],
) {
    for (agent, account) in agents[..3].iter().zip(["X", "X", "Y"]) {
        assert_eq!(
            consumer::call(f, &agent.token, "accounts")
                .await
                .text()
                .await
                .unwrap(),
            account
        );
    }
    assert_eq!(reference.snapshot().await, ([2, 1, 0], 3));
    let response = consumer::call(f, &agents[0].token, "customer-jobs").await;
    assert_eq!(
        response.json::<Value>().await.unwrap()["account"],
        "customer-beta"
    );
    assert_eq!(customer.received_requests().await.unwrap().len(), 1);
    clear_denies(f, reference, &agents[0]).await;
}

async fn clear_denies(f: &Fixture, reference: &upstream::Receiver, agent: &setup::Agent) {
    setup::clear(f, agent);
    upstream::denied(
        f,
        reference,
        Some(&agent.token),
        "accounts/check",
        403,
        "tool_not_allowed",
    )
    .await;
}

pub(super) fn authority(f: &Fixture, agent: &str) -> Vec<Value> {
    vec![
        f.op(&["agent", "get", agent]),
        f.op(&["agent", "credentials", "list", agent]),
    ]
}

fn publish(f: &Fixture, customer: &str) {
    let guide = include_str!("../../docs/user/operator/connector-onboarding.md");
    let mut command = docs::fixture(f, guide, "service-descriptions");
    command
        .env("REPO_ROOT", env!("CARGO_MANIFEST_DIR"))
        .env("CUSTOMER_URL", customer);
    assert!(
        process::run(command).status.success(),
        "shipped descriptor commands"
    );
}

fn grant_customer(f: &Fixture, agent: &str) {
    f.op(&[
        "agent",
        "set-credential",
        agent,
        "customer-jobs",
        "--auth",
        "header=x-customer-key:SMOKE_Y",
    ]);
    let output = process::run(f.cli(&[
        "agent",
        "modify",
        agent,
        "--allowlist",
        "accounts,customer-jobs",
    ]));
    assert!(output.status.success());
}

async fn customer() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(|request: &wiremock::Request| {
            assert_eq!(request.method.as_str(), "GET");
            assert_eq!(request.url.path(), "/v2/jobs");
            assert_eq!(request.url.query(), Some("limit=2"));
            assert_eq!(request.headers.get("x-customer-key").unwrap(), upstream::Y);
            assert!(!request.headers.contains_key("authorization"));
            ResponseTemplate::new(200)
                .set_body_json(json!({"account":"customer-beta", "jobs":["demo-job"]}))
        })
        .mount(&server)
        .await;
    server
}
