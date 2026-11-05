use super::provider::Provider;
use crate::{
    migrations,
    oauth::{OauthSessionRepository, SealingKey, refresh::refresh_selected_session},
    registrations::AuthSpec,
};
use secrecy::ExposeSecret;
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

pub struct ChildGuard(pub Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
pub struct Fixture {
    dir: tempfile::TempDir,
}
const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

impl Fixture {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pool = migrations::open_and_migrate(&dir.path().join("state.db"))
            .await
            .unwrap();
        OauthSessionRepository::new(pool.clone())
            .create(
                &key(),
                "fixture",
                "reader",
                "synthetic-old-refresh",
                Some("synthetic-old-access"),
                Some(i64::MAX),
                "read",
            )
            .await
            .unwrap();
        pool.close().await;
        Self { dir }
    }
    pub fn spawn(&self, point: &str, url: &str) -> ChildGuard {
        ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "oauth::refresh::recovery_process::worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env_clear()
                .env("OAUTH_RECOVERY_DB", self.dir.path().join("state.db"))
                .env("OAUTH_RECOVERY_POINT", point)
                .env("OAUTH_RECOVERY_URL", url)
                .env("OAUTH_RECOVERY_OBSERVED", self.dir.path().join("observed"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    pub async fn observed(&self, point: &str, provider: &Provider) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let ready = if point == "consumed" {
                    provider.consumed() == 1
                } else {
                    std::fs::read_to_string(self.dir.path().join("observed"))
                        .is_ok_and(|s| s == point)
                };
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("acknowledged production barrier");
    }
    pub async fn assert_state(&self, point: &str) {
        let pool = migrations::open_and_migrate(&self.dir.path().join("state.db"))
            .await
            .unwrap();
        let row = OauthSessionRepository::new(pool.clone())
            .get(&key(), "fixture", "reader")
            .await
            .unwrap()
            .unwrap();
        let complete = point == "committed";
        assert_eq!(row.refresh_pending, !complete);
        assert_eq!(
            row.access_token.unwrap().expose_secret(),
            if complete {
                "synthetic-new-access"
            } else {
                "synthetic-old-access"
            }
        );
        assert_eq!(
            row.refresh_token.expose_secret(),
            if complete {
                "synthetic-new-refresh"
            } else {
                "synthetic-old-refresh"
            }
        );
        pool.close().await;
    }
}

fn key() -> SealingKey {
    SealingKey::from_b64(KEY).unwrap()
}

pub async fn worker() {
    let path = std::env::var("OAUTH_RECOVERY_DB").unwrap();
    let pool = migrations::open_and_migrate(Path::new(&path))
        .await
        .unwrap();
    let repo = OauthSessionRepository::new(pool.clone());
    let session = repo
        .get(&key(), "fixture", "reader")
        .await
        .unwrap()
        .unwrap();
    let url = std::env::var("OAUTH_RECOVERY_URL").unwrap();
    let auth = selection(&url);
    if std::env::var("OAUTH_RECOVERY_POINT").unwrap() == "restart" && !session.refresh_pending {
        assert_eq!(
            session.access_token.unwrap().expose_secret(),
            "synthetic-new-access"
        );
    } else {
        assert!(
            refresh_selected_session(&repo, &auth, &key(), &reqwest::Client::new(), &session)
                .await
                .is_err()
        );
    }
    pool.close().await;
}

fn selection(url: &str) -> AuthSpec {
    AuthSpec::OauthDeviceCode {
        client_id: "synthetic".into(),
        device_url: format!("{url}/device"),
        token_url: format!("{url}/token"),
        scopes: vec![],
        session_label: Some("reader".into()),
    }
}
