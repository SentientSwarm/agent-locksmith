use super::{fixture::Fixture, oauth_provider::Provider, oauth_setup as setup, process, upstream};

pub async fn exercise(bootstrap: bool, fail: bool) {
    let receiver = upstream::Receiver::start().await;
    let provider = Provider::start().await;
    let mut f = Fixture::new(&receiver.server.uri());
    f.start_with_env(setup::ENV).await;
    let agent = setup::enroll(&f, &provider).await;
    let before = setup::authority(&f, &agent);
    if !bootstrap {
        provider.expiry(1);
        setup::connect(&f);
    }
    provider.expiry(3600);
    provider.hold(fail);
    let pending = attempt(&f, &agent.token, bootstrap);
    provider.arrived().await;
    setup::revoke(&f); // Must finish while the old exchange still holds the lock.
    provider.release();
    let status = pending.await.unwrap();
    assert_eq!(status, if bootstrap { 1 } else { 503 });
    assert_eq!(receiver.snapshot().await, ([0, 0, 0], 0));
    assert_eq!(setup::authority(&f, &agent), before);
    replacement(&mut f, &receiver, &agent.token).await;
    println!(
        "OAuth bootstrap={bootstrap} failure={fail}: revoke during pending exchange; old receiver=0 replacement=2 including restart"
    );
    setup::safe_reads(&f);
    f.cleanup();
}

fn attempt(f: &Fixture, token: &str, bootstrap: bool) -> tokio::task::JoinHandle<i32> {
    if bootstrap {
        let command = setup::bootstrap(f);
        tokio::task::spawn_blocking(move || {
            let output = process::run(command);
            setup::safe(&String::from_utf8_lossy(&output.stdout));
            setup::safe(&String::from_utf8_lossy(&output.stderr));
            output.status.code().unwrap()
        })
    } else {
        let request = f.http.get(f.url("/api/accounts/check")).bearer_auth(token);
        tokio::spawn(async move {
            let response = request.send().await.unwrap();
            let status = response.status().as_u16() as i32;
            setup::safe(&response.text().await.unwrap());
            status
        })
    }
}

async fn replacement(f: &mut Fixture, receiver: &upstream::Receiver, token: &str) {
    setup::connect(f);
    upstream::allowed(f, receiver, token, "accounts/check", "Y").await;
    f.stop();
    f.start_with_env(setup::ENV).await;
    upstream::allowed(f, receiver, token, "accounts/check", "Y").await;
    assert_eq!(receiver.snapshot().await, ([0, 2, 0], 2));
}
