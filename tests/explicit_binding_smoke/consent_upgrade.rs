//! Migration 0015 rebuilds oauth_sessions. An actual schema-14 daemon creates
//! legacy custody; the current daemon must preserve it exactly, and the prior
//! binary must refuse the upgraded database before any listener.
use super::{
    fixture::Fixture, migration, oauth_provider::Provider, oauth_setup as setup, oauth_upgrade,
    upstream,
};

pub async fn exercise() {
    let prior = std::env::var("LOCKSMITH_CONSENT_PRIOR_DAEMON").expect("explicit schema14 binary");
    let receiver = upstream::Receiver::start().await;
    let provider = Provider::start().await;
    let mut f = Fixture::new(&receiver.server.uri());
    f.start_with_env(&[
        ("LOCKSMITH_OAUTH_SEALING_KEY", setup::KEY),
        ("LOCKSMITHD_BIN", &prior),
    ])
    .await;
    assert_eq!(oauth_upgrade::version(&f), "14");
    let agent = setup::enroll(&f, &provider).await;
    setup::connect(&f);
    let authority = setup::authority(&f, &agent);
    f.stop();
    let before = snapshot(&f);
    f.start_with_env(setup::ENV).await;
    assert_eq!(oauth_upgrade::version(&f), "26");
    assert_eq!(
        snapshot(&f),
        before,
        "migrations 0015-0026 changed legacy custody"
    );
    assert_eq!(
        migration::sqlite(&f, &f.db, "SELECT DISTINCT kind FROM oauth_sessions;").trim(),
        "legacy"
    );
    assert_eq!(setup::authority(&f, &agent), authority);
    upstream::allowed(&f, &receiver, &agent.token, "accounts/check", "Y").await;
    f.stop();
    oauth_upgrade::refused(&f, &prior, 15);
    f.start_with_env(setup::ENV).await;
    upstream::allowed(&f, &receiver, &agent.token, "accounts/check", "Y").await;
    f.cleanup();
    println!(
        "actual schema 14 -> 26 preserves sealed custody, incarnations, versions, high-water and grants; prior refuses before listeners; restart passes"
    );
}

/// Sealed bytes, identity columns and the AUTOINCREMENT high-water mark.
fn snapshot(f: &Fixture) -> (String, String, String) {
    (
        oauth_upgrade::sealed(f),
        migration::sqlite(
            f,
            &f.db,
            "SELECT json_array(incarnation,token_version) FROM oauth_sessions ORDER BY incarnation;",
        ),
        migration::sqlite(
            f,
            &f.db,
            "SELECT seq FROM sqlite_sequence WHERE name='oauth_sessions';",
        ),
    )
}
