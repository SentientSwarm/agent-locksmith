#[allow(dead_code)]
#[path = "native_process/fixture.rs"]
mod fixture;
#[path = "definition_process/invalid.rs"]
mod invalid;
#[allow(dead_code)]
#[path = "native_process/observations.rs"]
mod observations;
#[allow(dead_code)]
#[path = "native_process/pki.rs"]
mod pki;
#[path = "explicit_binding_smoke/process.rs"]
mod process;
#[path = "native_process/receiver.rs"]
mod receiver;
#[path = "definition_process/support.rs"]
mod support;
#[path = "definition_process/upgrade.rs"]
mod upgrade;
#[allow(dead_code)]
#[path = "native_process/wire.rs"]
mod wire;
#[path = "definition_process/workflow.rs"]
mod workflow;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_cli_definition_authoring_is_disabled_and_has_zero_provider_effects() {
    workflow::exercise().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires LOCKSMITH_DEFINITION_PRIOR_DAEMON from accepted bb1feae"]
async fn actual_schema11_upgrade_preserves_authority_and_prior_refuses_before_listeners() {
    upgrade::exercise().await;
}
