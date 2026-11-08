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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_refresh_actual_cli_rotation_and_reconnect() {
    consent::refresh::journey().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_refresh_postclaim_refusals_stay_pending() {
    consent::refresh::refusals().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_refresh_held_consumption_loses_disconnect_or_crash() {
    consent::refresh::late().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_refresh_embedded_return_and_startup_error_join_owner() {
    consent::refresh::ownership().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit retained prior (schema-15 or schema-16) CLI/daemon paths"]
async fn controlled_refresh_actual_prior_migration_refusal_reopen() {
    consent::refresh::upgrade().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_native_actual_consent_selection_dispatch_and_refresh() {
    consent::native::journey().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controlled_native_refresh_disconnect_and_expiry_before_admission() {
    consent::native::races().await;
}
