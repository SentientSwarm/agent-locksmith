//! Library-worker phase barriers, separate from shipping daemon crash tests.
use super::*;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};
const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn wait(path: &Path) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("phase witness");
}
fn spawn(root: &Path, point: &str) -> ChildGuard {
    let log = std::fs::File::create(root.join(format!("worker-{point}.log"))).unwrap();
    ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "oauth::consent::tests::refresh_cases::process::worker",
                "--ignored",
                "--nocapture",
            ])
            .env("CONTROLLED_REFRESH_WORKER", root)
            .env("CONTROLLED_REFRESH_MODE", point)
            .env("OAUTH_RECOVERY_POINT", format!("controlled_{point}"))
            .env("OAUTH_RECOVERY_OBSERVED", root.join("observed"))
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    )
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killed_workers_preserve_pending_or_complete_pair_without_replay() {
    for point in ["claimed", "consumed", "decoded", "committed"] {
        let mut f = Fixture::new().await;
        let root = f._dir.path();
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        for name in ["ca.pem", "server.pem"] {
            std::fs::write(root.join(name), cert.cert.pem()).unwrap();
        }
        std::fs::write(root.join("server.key"), cert.key_pair.serialize_pem()).unwrap();
        let log = std::fs::File::create(root.join("receiver.log")).unwrap();
        let mut provider = ChildGuard(
            Command::new("python3")
                .args([
                    "-B",
                    concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/oauth_consent/receiver.py"
                    ),
                ])
                .arg(root)
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        );
        wait(&root.join("provider-port.json")).await;
        let port: u16 =
            serde_json::from_slice(&std::fs::read(root.join("provider-port.json")).unwrap())
                .unwrap();
        let mut config = f.rt.config.clone();
        let p = &mut config.profiles[0];
        p.issuer = format!("https://127.0.0.1:{port}");
        p.authorization_endpoint = format!("{}/authorize", p.issuer);
        p.token_endpoint = format!("{}/token", p.issuer);
        p.resource = format!("{}/mcp/readonly", p.issuer);
        f.repo.delete("fixture").await.unwrap();
        f.repo
            .create(&Registration::new(
                "fixture".into(),
                Kind::Tool,
                "controlled".into(),
                p.resource.clone(),
                AuthSpec::OauthPkce {
                    client_id: p.client_id.clone(),
                    redirect_uri: p.redirect_uri.clone(),
                    scopes: vec!["read".into()],
                    auth_url: p.authorization_endpoint.clone(),
                    token_url: p.token_endpoint.clone(),
                    session_label: None,
                },
            ))
            .await
            .unwrap();
        std::fs::write(root.join("profile.json"), serde_json::to_vec(p).unwrap()).unwrap();
        f.rt = Runtime::new(
            f.rt.pool.clone(),
            SealingKey::from_b64(KEY).unwrap(),
            config,
            RefreshOwner::default(),
        )
        .await
        .unwrap();
        let (_, a) = f.claimed("crash").await;
        let token=token::decode(&f.rt.config.profiles[0],br#"{"access_token":"fixture-access-204","refresh_token":"fixture-refresh-0","token_type":"Bearer"}"#).unwrap();
        f.rt.publish(&a, &token).await.unwrap();
        if point == "consumed" {
            std::fs::write(root.join("hold-refresh"), "held").unwrap();
        }
        let mut child = spawn(root, point);
        wait(&root.join(if point == "consumed" {
            "entered-refresh"
        } else {
            "observed"
        }))
        .await;
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        if point == "consumed" {
            std::fs::write(root.join("release-refresh"), "release").unwrap();
            wait(&root.join("finished-refresh")).await;
        }
        let row = sqlx::query("SELECT * FROM oauth_sessions WHERE session_label='crash'")
            .fetch_one(&f.rt.pool)
            .await
            .unwrap();
        let complete = point == "committed";
        assert_eq!(row.get::<bool, _>("refresh_pending"), !complete);
        assert_eq!(
            row.get::<i64, _>("token_version"),
            if complete { 2 } else { 1 }
        );
        assert_eq!(
            f.rt.key
                .unseal(
                    row.get("access_token_ciphertext"),
                    row.get("access_token_nonce")
                )
                .unwrap(),
            if complete {
                b"fixture-access-1".as_slice()
            } else {
                b"fixture-access-204".as_slice()
            }
        );
        assert_eq!(
            f.rt.key
                .unseal(
                    row.get("refresh_token_ciphertext"),
                    row.get("refresh_token_nonce")
                )
                .unwrap(),
            if complete {
                b"fixture-refresh-1".as_slice()
            } else {
                b"fixture-refresh-0".as_slice()
            }
        );
        let mut restart = spawn(root, "restart");
        assert!(restart.0.wait().unwrap().success());
        let counts: Value = std::fs::read(root.join("counts.json"))
            .map(|v| serde_json::from_slice(&v).unwrap())
            .unwrap_or(json!({"refresh":0,"consumed":0,"issued":0}));
        let expected = i64::from(point != "claimed");
        assert_eq!(counts["refresh"], expected);
        assert_eq!(counts["consumed"], expected);
        assert_eq!(counts["issued"], expected);
        println!(
            "controlled library SIGKILL/reap/same-state restart {point}: arrivals/consumed/issued={expected}, version={}, pending={}",
            row.get::<i64, _>("token_version"),
            !complete
        );
        provider.0.kill().unwrap();
        provider.0.wait().unwrap();
        f.rt.pool.close().await;
    }
}
#[tokio::test]
#[ignore = "parent supplies same-state synthetic custody and retained receiver"]
async fn worker() {
    let Some(root) = std::env::var_os("CONTROLLED_REFRESH_WORKER") else {
        return;
    };
    let root = PathBuf::from(root);
    crate::admin::https::install_crypto_provider_once();
    let p: config::Profile =
        serde_json::from_slice(&std::fs::read(root.join("profile.json")).unwrap()).unwrap();
    let config = config::Config {
        callback: config::Callback {
            address: "127.0.0.1:19294".parse().unwrap(),
            cert_path: root.join("ca.pem"),
            key_path: root.join("server.key"),
        },
        profiles: vec![p],
    };
    let pool = migrations::open_and_migrate(&root.join("state.db"))
        .await
        .unwrap();
    let rt = Runtime::new(
        pool.clone(),
        SealingKey::from_b64(KEY).unwrap(),
        config,
        RefreshOwner::default(),
    )
    .await
    .unwrap();
    let view = rt.account("owner", "fixture", "crash").await.unwrap();
    if std::env::var("CONTROLLED_REFRESH_MODE").unwrap() != "restart" {
        let (r, _) = rt
            .refresh(
                "owner",
                "fixture",
                "crash",
                view["revision"].as_str().unwrap(),
            )
            .await;
        r.unwrap();
    } else if view["refresh_pending"] == true {
        let (r, _) = rt
            .refresh(
                "owner",
                "fixture",
                "crash",
                view["revision"].as_str().unwrap(),
            )
            .await;
        assert_eq!(r.unwrap_err().0, "reconnect_required");
    }
    pool.close().await;
}
