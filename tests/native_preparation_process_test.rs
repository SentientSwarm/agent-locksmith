#![allow(dead_code)] // Existing shared process helpers cover other targets too.
#[path = "native_preparation/bearer_listener.rs"]
mod bearer_listener;
#[path = "native_preparation/bounds.rs"]
mod bounds;
#[path = "native_process/fixture.rs"]
mod fixture;
#[path = "native_preparation/process_flow.rs"]
mod flow;
#[path = "native_process/observations.rs"]
mod observations;
#[path = "native_process/pki.rs"]
mod pki;
#[path = "explicit_binding_smoke/process.rs"]
mod process;
#[path = "native_preparation/races.rs"]
mod races;
#[path = "native_preparation/receiver.rs"]
mod receiver;
#[path = "native_preparation/upgrade.rs"]
mod upgrade;
#[path = "native_preparation/upgrade_http.rs"]
mod upgrade_http;
#[path = "native_process/wire.rs"]
mod wire;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_cli_tls_observe_review_grant_and_refuse_calls() {
    flow::journey().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires preserved accepted schema13 daemon"]
async fn actual_schema13_upgrade_and_prior_refusal() {
    upgrade::exercise().await;
}
