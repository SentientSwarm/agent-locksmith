use super::*;
use crate::migrations::open_and_migrate;
use crate::oauth::sealing::SealingKey;
use secrecy::ExposeSecret;
use tempfile::TempDir;

async fn fresh_repo() -> (TempDir, OauthSessionRepository, SealingKey) {
    let dir = TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("locksmith.db"))
        .await
        .unwrap();
    let repo = OauthSessionRepository::new(pool);
    let key = SealingKey::generate().unwrap();
    (dir, repo, key)
}

const DEF: &str = DEFAULT_SESSION_LABEL;

mod labels;
mod tokens;
