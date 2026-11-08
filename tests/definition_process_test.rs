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

#[path = "definition_process/upgrade18.rs"]
mod upgrade18;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an actual retained schema-17 CLI and daemon and their revision"]
async fn definition_schema17_prior_refusal_reopen() {
    upgrade18::exercise().await;
}

#[path = "definition_process/upgrade20.rs"]
mod upgrade20;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an actual retained schema-19 daemon in LOCKSMITH_POLICY_PRIOR_DAEMON"]
async fn definition_policy_schema19_prior_refusal_reopen() {
    upgrade20::exercise().await;
}

#[path = "definition_process/upgrade21.rs"]
mod upgrade21;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an actual retained schema-20 daemon in LOCKSMITH_SLACK_PRIOR_DAEMON"]
async fn slack_schema20_prior_refusal_ciphertext_highwater_reopen() {
    upgrade21::exercise().await;
}
