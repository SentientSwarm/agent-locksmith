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

#[path = "oauth_consent/callback_tests.rs"]
mod callback_tests;
#[path = "oauth_consent/metadata_tests.rs"]
mod metadata_tests;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hosted_native_actual_consent_projection_selection_dispatch_and_refresh() {
    consent::native::hosted_journey().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hosted_public_callback_is_bound_to_selected_attempt_not_other_profile() {
    consent::hosted::public_callback().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an explicit retained schema-18 daemon"]
async fn hosted_actual_schema18_refusal_and_current_reopen() {
    consent::hosted::prior_upgrade().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hosted_catalog_refuses_partial_missing_duplicate_and_changed_policy() {
    consent::native::hosted_catalog_refusals().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_confidential_actual_promotion_consent_verifier_and_native_journey() {
    consent::slack::journey().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_token_transport_failure_preserves_http() {
    consent::slack::failures::token_http().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_identity_token_actual_header_body_deadlines() {
    consent::slack::failures::deadlines().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_native_actual_header_body_sse_deadlines() {
    consent::slack::failures::native_deadlines().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_optional_access_only() {
    consent::slack::lifecycle::optional().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_refresh_nullable_persistence() {
    consent::slack::lifecycle::refresh_optionality().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_cancel_crash_pending() {
    consent::slack::lifecycle::cancel_and_crash().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_client_boundaries_no_fallback_or_orphan() {
    consent::slack::clients::boundaries().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_client_wrong_plaintext_is_received_and_refused() {
    consent::slack::clients::wrong_client().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_dispatch_actual_header_body_sse_deadlines() {
    consent::slack::dispatch::deadlines().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_client_retirement_prevents_late_exchange_publication() {
    consent::slack::retirement::held_exchange().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_client_retirement_prevents_late_refresh_publication() {
    consent::slack::retirement::held_refresh().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_advertised_resource_actual_promoted_transport() {
    consent::slack::resource::journey().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_resource_endpoint_promotion_refuses_without_mutation() {
    consent::slack::resource_denials::endpoints().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slack_resource_echo_refuses_publication_and_refresh_replay() {
    consent::slack::resource_denials::echo().await;
}
