pub use agent_locksmith::oauth::{
    sealing::SealingKey,
    session::{OauthSession, OauthSessionRepository},
};
pub use secrecy::ExposeSecret;
pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub async fn fixture() -> Result<(tempfile::TempDir, OauthSessionRepository, SealingKey), Error> {
    let dir = tempfile::tempdir()?;
    let pool = agent_locksmith::migrations::open_and_migrate(&dir.path().join("state.db")).await?;
    Ok((
        dir,
        OauthSessionRepository::new(pool),
        SealingKey::generate()?,
    ))
}

pub async fn seed(
    repo: &OauthSessionRepository,
    key: &SealingKey,
    value: &str,
) -> Result<OauthSession, Error> {
    Ok(repo
        .create(
            key,
            "fixture",
            "reader",
            value,
            Some(value),
            Some(3600),
            "read",
        )
        .await?)
}

pub async fn pool(dir: &tempfile::TempDir) -> sqlx::SqlitePool {
    agent_locksmith::migrations::open_and_migrate(&dir.path().join("state.db"))
        .await
        .unwrap()
}

pub async fn current(repo: &OauthSessionRepository, key: &SealingKey) -> OauthSession {
    repo.get(key, "fixture", "reader").await.unwrap().unwrap()
}

pub fn assert_pair(s: &OauthSession, access: &str, refresh: &str) {
    assert_eq!(s.access_token.as_ref().unwrap().expose_secret(), access);
    assert_eq!(s.refresh_token.expose_secret(), refresh);
}

pub fn stale(result: Result<(), agent_locksmith::oauth::OauthSessionError>) {
    assert!(matches!(
        result,
        Err(agent_locksmith::oauth::OauthSessionError::Stale)
    ));
}
