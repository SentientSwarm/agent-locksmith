use super::{
    fixture::Fixture, oauth_setup as setup, recovery_common as common, recovery_provider::Provider,
    upstream,
};

pub async fn exercise(bootstrap: bool) {
    let receiver = upstream::Receiver::start().await;
    let provider = Provider::start().await;
    let mut f = Fixture::new(&receiver.server.uri());
    f.start_with_env(setup::ENV).await;
    let agent = setup::enroll_url(&f, &provider.url).await;
    let authority = setup::authority(&f, &agent);
    if !bootstrap {
        common::connect(&f, "synthetic-first-refresh");
        common::expiry(&f, 1);
    }
    provider.hold();
    let request = common::attempt(&f, &agent.token, bootstrap);
    provider.arrived().await;
    common::pending(&f);
    common::expiry(&f, i64::MAX); // Even unexpired old access must be refused.
    let before = common::state(&f);
    kill(&mut f);
    request.await.unwrap();
    provider.release();
    f.start_with_env(setup::ENV).await; // Same DB/WAL; immediate background tick.
    verify(
        &f, &provider, &receiver, &agent, bootstrap, &before, &authority,
    )
    .await;
    reconnect(&mut f, &receiver, &agent.token).await;
    f.cleanup();
    provider.stop().await;
}
async fn reconnect(f: &mut Fixture, receiver: &upstream::Receiver, token: &str) {
    setup::revoke(f);
    common::connect(f, "synthetic-fresh-reconnect");
    upstream::allowed(f, receiver, token, "accounts/check", "Y").await;
    f.stop();
    f.start_with_env(setup::ENV).await;
    upstream::allowed(f, receiver, token, "accounts/check", "Y").await;
}

#[allow(clippy::too_many_arguments)]
async fn verify(
    f: &Fixture,
    provider: &Provider,
    receiver: &upstream::Receiver,
    agent: &super::setup::Agent,
    bootstrap: bool,
    before: &str,
    authority: &[serde_json::Value],
) {
    common::pending(f);
    common::denied(f, &agent.token).await;
    assert_eq!(common::state(f), before);
    assert_eq!(provider.counts().0, if bootstrap { 1 } else { 2 });
    assert_eq!(receiver.snapshot().await.1, 0);
    assert_eq!(setup::authority(f, agent), authority);
}

fn kill(f: &mut Fixture) {
    let mut daemon = f.daemon.take().unwrap();
    daemon.0.kill().unwrap();
    assert!(!daemon.0.wait().unwrap().success());
}
