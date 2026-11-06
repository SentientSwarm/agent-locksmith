//! Process-death barriers compiled only into the Rust unit-test executable.
//! Shipping binaries contain neither the environment controls nor these waits.
use crate::oauth::OauthSession;

pub(crate) async fn reach(point: &str) {
    if std::env::var("OAUTH_RECOVERY_POINT").ok().as_deref() != Some(point) {
        return;
    }
    let path = std::env::var_os("OAUTH_RECOVERY_OBSERVED").expect("test barrier path");
    std::fs::write(path, point).unwrap();
    std::future::pending::<()>().await;
}

pub(crate) async fn complete(point: &str, session: &OauthSession) {
    // The child starts at version zero; only a completed claim reaches two.
    if session.token_version == 2 && !session.refresh_pending {
        reach(point).await;
    }
}
