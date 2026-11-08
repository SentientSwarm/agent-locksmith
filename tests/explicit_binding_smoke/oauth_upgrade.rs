use super::{
    fixture::Fixture, migration, oauth_provider::Provider, oauth_setup as setup, process, upstream,
};

pub async fn exercise() {
    let prior = std::env::var("LOCKSMITH_PRIOR_DAEMON").expect("explicit pre-0010 binary required");
    let receiver = upstream::Receiver::start().await;
    let provider = Provider::start().await;
    let mut f = Fixture::new(&receiver.server.uri());
    start_prior(&mut f, &prior).await;
    assert_eq!(version(&f), "9");
    let agent = setup::enroll(&f, &provider).await;
    setup::connect(&f);
    let authority = setup::authority(&f, &agent);
    f.stop();
    let before = sealed(&f);
    f.start_with_env(setup::ENV).await;
    assert_eq!(version(&f), "19");
    assert_eq!(
        sealed(&f),
        before,
        "migration changed existing sealed custody"
    );
    assert_eq!(setup::authority(&f, &agent), authority);
    upstream::allowed(&f, &receiver, &agent.token, "accounts/check", "Y").await;
    f.stop();
    refused(&f, &prior, 10);
    f.start_with_env(setup::ENV).await;
    upstream::allowed(&f, &receiver, &agent.token, "accounts/check", "Y").await;
    f.cleanup();
    println!(
        "Actual pre-0010 daemon -> migrated current daemon: custody/grants preserved, prior binary refuses before listeners, current restart works"
    );
}

pub(super) fn version(f: &Fixture) -> String {
    migration::sqlite(f, &f.db, "SELECT MAX(version) FROM _sqlx_migrations;")
        .trim()
        .into()
}
pub(super) fn sealed(f: &Fixture) -> String {
    migration::sqlite(
        f,
        &f.db,
        "SELECT json_array(name, session_label,
        hex(refresh_token_ciphertext), hex(refresh_token_nonce),
        hex(access_token_ciphertext), hex(access_token_nonce), access_token_expires_at,
        scope, degraded, created_at, updated_at, account_id) FROM oauth_sessions;",
    )
}
pub(super) fn refused(f: &Fixture, prior: &str, migration: u32) {
    let _ = std::fs::remove_file(&f.socket);
    let mut c = process::command(prior);
    c.arg("--config")
        .arg(&f.config)
        .env("LOCKSMITH_OAUTH_SEALING_KEY", setup::KEY);
    let output = process::run(c);
    assert!(!output.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains(&format!("migration {migration}")) && text.contains("missing"),
        "expected migration refusal; output withheld"
    );
    assert!(!f.socket.exists(), "prior admin listener opened");
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", f.port)).is_err(),
        "prior agent listener opened"
    );
}

async fn start_prior(f: &mut Fixture, prior: &str) {
    f.start_with_env(&[
        ("LOCKSMITH_OAUTH_SEALING_KEY", setup::KEY),
        ("LOCKSMITHD_BIN", prior),
    ])
    .await;
}
