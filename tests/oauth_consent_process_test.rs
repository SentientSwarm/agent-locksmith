#![allow(dead_code)]
#[path = "oauth_consent/process.rs"]
mod consent;
#[path = "native_process/fixture.rs"]
mod fixture;
#[path = "native_process/observations.rs"]
mod observations;
#[path = "native_process/pki.rs"]
mod pki;
#[path = "explicit_binding_smoke/process.rs"]
mod process;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_consent_actual_cli_and_receiving_identity() {
    consent::journey().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_consent_late_callback_cannot_publish_after_cancel_or_stop() {
    consent::late().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_consent_principal_is_public_id_across_bearer_and_mtls() {
    consent::principal().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_consent_checks_fixed_arguments_before_identity_calls() {
    consent::schemas().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_consent_orphan_remains_owner_disconnectable() {
    consent::orphan().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_consent_callback_bind_failure_precedes_serving() {
    consent::callback_bind_failure().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_consent_embedded_return_owns_connections() {
    consent::embedded().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "isolated child process for owned embedded daemon"]
async fn embedded_consent_worker() {
    consent::embedded_worker().await;
}
