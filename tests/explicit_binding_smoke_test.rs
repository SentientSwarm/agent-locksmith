//! Saved SM01–SM05: actual disposable daemon, CLI, SQLite and receiving upstream.
//! No installed service, provider credentials or application database is used.
#[path = "explicit_binding_smoke/docs.rs"]
mod docs;
#[path = "explicit_binding_smoke/fixture.rs"]
mod fixture;
#[path = "explicit_binding_smoke/guidance.rs"]
mod guidance;
#[path = "explicit_binding_smoke/migration.rs"]
mod migration;
#[path = "explicit_binding_smoke/process.rs"]
mod process;
#[path = "explicit_binding_smoke/safety.rs"]
mod safety;
#[path = "explicit_binding_smoke/setup.rs"]
mod setup;
#[path = "explicit_binding_smoke/upstream.rs"]
mod upstream;
#[path = "explicit_binding_smoke/workflow.rs"]
mod workflow;

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
