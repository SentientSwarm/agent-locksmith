//! Saved SM01–SM05: actual disposable daemon, CLI, SQLite and receiving upstream.
//! No installed service, provider credentials or application database is used.
#[path = "explicit_binding_smoke/connector_validation.rs"]
mod connector_validation;
#[path = "explicit_binding_smoke/customer.rs"]
mod customer;
#[path = "explicit_binding_smoke/docs.rs"]
mod docs;
#[path = "explicit_binding_smoke/fixture.rs"]
mod fixture;
#[path = "explicit_binding_smoke/guidance.rs"]
mod guidance;
#[path = "explicit_binding_smoke/http_grants.rs"]
mod http_grants;
#[path = "explicit_binding_smoke/lifecycle.rs"]
mod lifecycle;
#[path = "explicit_binding_smoke/migration.rs"]
mod migration;
#[path = "explicit_binding_smoke/process.rs"]
mod process;
#[path = "explicit_binding_smoke/safety.rs"]
mod safety;
#[path = "explicit_binding_smoke/service_description.rs"]
mod service_description;
#[path = "explicit_binding_smoke/setup.rs"]
mod setup;
#[path = "explicit_binding_smoke/upstream.rs"]
mod upstream;
#[path = "explicit_binding_smoke/workflow.rs"]
mod workflow;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_daemon_http_service_descriptions() {
    service_description::exercise().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_daemon_connector_validation_preserves_authority() {
    connector_validation::exercise().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_daemon_agent_token_lifecycle() {
    lifecycle::exercise().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_daemon_operator_cutover_sm01_through_sm05() {
    let receiver = upstream::Receiver::start().await;
    let mut f = fixture::Fixture::new(&receiver.server.uri());
    f.start().await;
    let agents = setup::enroll(&f).await;
    workflow::exercise(&f, &receiver, &agents).await;
    migration::cutover(&mut f, &receiver, &agents).await;
    safety::verify(&f, &agents).await;
    let (counts, received) = receiver.snapshot().await;
    assert_eq!(counts.iter().sum::<usize>(), received);
    println!(
        "receiving totals: X={} Y={} noauth={} requests={received}",
        counts[0], counts[1], counts[2]
    );
    let address = receiver.server.address().to_owned();
    f.cleanup();
    drop(receiver);
    upstream::closed(address).await;
    println!("SM01–SM05 PASS; fixture daemon reaped, state removed, upstream released");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_daemon_finite_grants_activation_and_replacement() {
    http_grants::exercise().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_daemon_reference_and_customer_service() {
    customer::exercise().await;
}

#[path = "explicit_binding_smoke/oauth_lifecycle.rs"]
mod oauth_lifecycle;
#[path = "explicit_binding_smoke/oauth_provider.rs"]
mod oauth_provider;
#[path = "explicit_binding_smoke/oauth_setup.rs"]
mod oauth_setup;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_daemon_oauth_revoke_during_exchange() {
    for bootstrap in [true, false] {
        for fail in [false, true] {
            oauth_lifecycle::exercise(bootstrap, fail).await;
        }
    }
}

#[path = "explicit_binding_smoke/oauth_upgrade.rs"]
mod oauth_upgrade;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires LOCKSMITH_PRIOR_DAEMON pointing to a pre-0010 binary"]
async fn actual_daemon_oauth_upgrade_and_prior_binary_refusal() {
    oauth_upgrade::exercise().await;
}
#[path = "explicit_binding_smoke/native_upgrade.rs"]
mod native_upgrade;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires LOCKSMITH_NATIVE_PRIOR_DAEMON and sibling CLI from accepted pre-0011 revision"]
async fn actual_daemon_native_upgrade_and_prior_binary_refusal() {
    native_upgrade::exercise().await;
}

#[path = "explicit_binding_smoke/recovery_common.rs"]
mod recovery_common;
#[path = "explicit_binding_smoke/recovery_crash.rs"]
mod recovery_crash;
#[path = "explicit_binding_smoke/recovery_provider.rs"]
mod recovery_provider;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_daemon_refresh_crash_requires_fresh_reconnect() {
    for bootstrap in [true, false] {
        recovery_crash::exercise(bootstrap).await;
    }
}

#[path = "explicit_binding_smoke/recovery_embedded.rs"]
mod recovery_embedded;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_daemon_joins_bootstrap_refresh_before_return() {
    recovery_embedded::exercise(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_daemon_joins_inline_refresh_before_return() {
    recovery_embedded::exercise(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated embedding worker launched by parent"]
async fn embedded_oauth_recovery_worker() {
    recovery_embedded::worker().await;
}

#[path = "explicit_binding_smoke/recovery_upgrade.rs"]
mod recovery_upgrade;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires LOCKSMITH_RECOVERY_PRIOR_DAEMON built from schema12"]
async fn actual_daemon_refresh_upgrade_and_prior_refusal() {
    recovery_upgrade::exercise().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_error_does_not_spawn_refresh() {
    recovery_embedded::startup_failure().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated startup-error worker launched by parent"]
async fn oauth_startup_failure_worker() {
    recovery_embedded::startup_worker().await;
}
