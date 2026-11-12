use super::{
    fixture::Fixture, migration, oauth_provider::Provider, oauth_setup as setup, oauth_upgrade,
    upstream,
};

pub async fn exercise() {
    let prior = std::env::var("LOCKSMITH_RECOVERY_PRIOR_DAEMON").expect("explicit schema12 binary");
    let receiver = upstream::Receiver::start().await;
    let provider = Provider::start().await;
    let mut f = Fixture::new(&receiver.server.uri());
    f.start_with_env(&[
        ("LOCKSMITH_OAUTH_SEALING_KEY", setup::KEY),
        ("LOCKSMITHD_BIN", &prior),
    ])
    .await;
    assert_eq!(oauth_upgrade::version(&f), "12");
    let agent = setup::enroll(&f, &provider).await;
    setup::connect(&f);
    let authority = setup::authority(&f, &agent);
    f.stop();
    let before = snapshot(&f);
    f.start_with_env(setup::ENV).await;
    verify(&f, &receiver, &agent, &authority, before).await;
    f.stop();
    oauth_upgrade::refused(&f, &prior, 13);
    f.start_with_env(setup::ENV).await;
    upstream::allowed(&f, &receiver, &agent.token, "accounts/check", "Y").await;
    f.cleanup();
    println!(
        "actual schema 12 -> 25 preserves sealed custody/incarnation/version/grants; prior refuses before listeners; restart passes"
    );
}
fn snapshot(f: &Fixture) -> (String, String) {
    (
        oauth_upgrade::sealed(f),
        migration::sqlite(
            f,
            &f.db,
            "SELECT json_array(incarnation,token_version) FROM oauth_sessions ORDER BY incarnation;",
        ),
    )
}

async fn verify(
    f: &Fixture,
    receiver: &upstream::Receiver,
    agent: &super::setup::Agent,
    authority: &[serde_json::Value],
    before: (String, String),
) {
    assert_eq!(oauth_upgrade::version(f), "25");
    assert_eq!(snapshot(f), before);
    assert_eq!(setup::authority(f, agent), authority);
    assert_eq!(
        f.op(&["oauth", "status", "accounts", "--label", "reader"])["refresh_pending"],
        false
    );
    upstream::allowed(f, receiver, &agent.token, "accounts/check", "Y").await;
}
