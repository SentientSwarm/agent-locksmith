use super::*;
use crate::{
    migrations,
    oauth::OauthSessionRepository,
    registrations::{AuthSpec, Kind, Registration, RegistrationRepository},
};
use serde_json::json;
use sqlx::Executor;

struct Fixture {
    _dir: tempfile::TempDir,
    rt: Arc<Runtime>,
    repo: RegistrationRepository,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_callback("127.0.0.1:19294".parse().unwrap()).await
    }
    /// A fixture whose callback listener can actually start at `address`.
    async fn with_callback(address: std::net::SocketAddr) -> Self {
        crate::admin::https::install_crypto_provider_once();
        let dir = tempfile::tempdir().unwrap();
        let ca = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca.cert.pem()).unwrap();
        std::fs::write(dir.path().join("key.pem"), ca.key_pair.serialize_pem()).unwrap();
        let profile = config::Profile {
            id: "fixture".into(),
            kind: "controlled-linear-v1".into(),
            selected_tools: vec![],
            client_id: "fixture-client".into(),
            client_generation: 1,
            issuer: "https://127.0.0.1:19293".into(),
            authorization_endpoint: "https://127.0.0.1:19293/authorize".into(),
            token_endpoint: "https://127.0.0.1:19293/token".into(),
            resource: "https://127.0.0.1:19293/mcp/readonly".into(),
            redirect_profile_id: "loopback".into(),
            redirect_uri: format!("https://{address}/oauth/callback"),
            expected_workspace: "00000000-0000-0000-0000-000000000041".into(),
            expected_user: "00000000-0000-0000-0000-000000000042".into(),
            ca_path: ca_path.clone(),
        };
        let config = config::Config {
            callback: config::Callback {
                address,
                cert_path: ca_path,
                key_path: dir.path().join("key.pem"),
            },
            profiles: vec![profile.clone()],
        };
        let pool = migrations::open_and_migrate(&dir.path().join("state.db"))
            .await
            .unwrap();
        let repo = RegistrationRepository::new(pool.clone());
        let registration = Registration::new(
            "fixture".into(),
            Kind::Tool,
            "controlled".into(),
            profile.resource.clone(),
            AuthSpec::OauthPkce {
                client_id: profile.client_id,
                redirect_uri: profile.redirect_uri,
                scopes: vec!["read".into()],
                auth_url: profile.authorization_endpoint,
                token_url: profile.token_endpoint,
                session_label: None,
            },
        );
        repo.create(&registration).await.unwrap();
        let rt = Runtime::new(
            pool,
            SealingKey::generate().unwrap(),
            config,
            RefreshOwner::default(),
        )
        .await
        .unwrap();
        Self {
            _dir: dir,
            rt,
            repo,
        }
    }
    async fn start(&self, label: &str) -> Value {
        let revision = self.rt.account("owner", "fixture", label).await.unwrap()["config_revision"]
            .as_i64()
            .unwrap();
        self.rt
            .start(
                "owner",
                "fixture",
                &Start {
                    session_label: label.into(),
                    auth_profile_id: "fixture".into(),
                    client_generation: 1,
                    requested_scopes: vec!["read".into()],
                    redirect_profile_id: "loopback".into(),
                    expected_config_revision: revision,
                },
            )
            .await
            .unwrap()
    }
    async fn claimed(&self, label: &str) -> (Value, sqlx::sqlite::SqliteRow) {
        let value = self.start(label).await;
        let url = reqwest::Url::parse(value["authorization_url"].as_str().unwrap()).unwrap();
        let state = url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .into_owned();
        let row = self
            .rt
            .claim(
                &state,
                &self.rt.config.profiles[0].issuer,
                "127.0.0.1:19294",
            )
            .await
            .unwrap();
        (value, row)
    }
    fn token(&self) -> token::Token {
        token::decode(
            &self.rt.config.profiles[0],
            br#"{"access_token":"fixture-access","token_type":"Bearer"}"#,
        )
        .unwrap()
    }
}
#[tokio::test]
async fn owner_absent_revision_and_commit_first_cancel() {
    let f = Fixture::new().await;
    let absent = f.rt.account("owner", "fixture", "one").await.unwrap();
    let (created, claimed) = f.claimed("one").await;
    assert_eq!(
        f.rt.account("other", "fixture", "one").await.unwrap_err().0,
        "not_found"
    );
    assert_eq!(
        f.rt.disconnect(
            "other",
            "fixture",
            "one",
            absent["revision"].as_str().unwrap()
        )
        .await
        .unwrap_err()
        .0,
        "not_found"
    );
    assert_eq!(
        f.rt.disconnect(
            "owner",
            "fixture",
            "one",
            absent["revision"].as_str().unwrap()
        )
        .await
        .unwrap_err()
        .0,
        "source_conflict"
    );
    let token = f.token();
    f.rt.quarantine(&claimed, &token).await.unwrap();
    let generation = f.rt.publish(&claimed, &token).await.unwrap();
    f.rt.cancel("owner", "fixture", created["attempt_id"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        f.rt.poll("owner", "fixture", created["attempt_id"].as_str().unwrap())
            .await
            .unwrap()["state"],
        "connected"
    );
    let account = f.rt.account("owner", "fixture", "one").await.unwrap();
    assert_eq!(account["account_generation"], generation);
    assert_eq!(account["state"], "connected_unbound");
    assert_eq!(account["granted_scope"], Value::Null);
    let legacy = OauthSessionRepository::new(f.rt.pool.clone());
    assert!(matches!(
        legacy.get(&f.rt.key, "fixture", "one").await,
        Err(crate::oauth::OauthSessionError::UnsupportedKind)
    ));
    assert!(legacy.list_all().await.unwrap().is_empty());
    assert!(
        legacy
            .list_pending_refresh(i64::MAX)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        legacy.delete("fixture", "one").await,
        Err(crate::oauth::OauthSessionError::UnsupportedKind)
    ));
    assert!(matches!(
        legacy
            .create(&f.rt.key, "fixture", "one", "legacy", None, None, "")
            .await,
        Err(crate::oauth::OauthSessionError::UnsupportedKind)
    ));
    let disconnected =
        f.rt.disconnect(
            "owner",
            "fixture",
            "one",
            account["revision"].as_str().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disconnected["account_generation"], generation);
    f.rt.pool.close().await;
}
#[tokio::test]
async fn late_publication_loses_cancel_disconnect_legacy_and_registration_aba() {
    for action in [
        "cancel",
        "disconnect",
        "legacy",
        "legacy_absent_revoke",
        "registration",
    ] {
        let f = Fixture::new().await;
        let (created, claimed) = f.claimed("held").await;
        let token = f.token();
        f.rt.quarantine(&claimed, &token).await.unwrap();
        match action {
            "cancel" => {
                f.rt.cancel("owner", "fixture", created["attempt_id"].as_str().unwrap())
                    .await
                    .unwrap()
            }
            "disconnect" => {
                let a = f.rt.account("owner", "fixture", "held").await.unwrap();
                f.rt.disconnect("owner", "fixture", "held", a["revision"].as_str().unwrap())
                    .await
                    .unwrap();
            }
            "legacy" => {
                let r = OauthSessionRepository::new(f.rt.pool.clone());
                r.create(&f.rt.key, "fixture", "held", "old", None, None, "")
                    .await
                    .unwrap();
                r.delete("fixture", "held").await.unwrap();
            }
            "legacy_absent_revoke" => {
                OauthSessionRepository::new(f.rt.pool.clone())
                    .delete("fixture", "held")
                    .await
                    .unwrap();
            }
            _ => {
                let r = f.repo.get("fixture").await.unwrap().unwrap();
                f.repo.delete("fixture").await.unwrap();
                f.repo.create(&r).await.unwrap();
            }
        }
        assert!(f.rt.publish(&claimed, &token).await.is_err(), "{action}");
        assert_eq!(
            f.rt.account("owner", "fixture", "held").await.unwrap()["state"],
            "absent"
        );
        let remaining:i64=sqlx::query_scalar("SELECT count(*) FROM oauth_consent_attempts WHERE verifier_ct IS NOT NULL OR quarantine_ct IS NOT NULL OR state_hash IS NOT NULL").fetch_one(&f.rt.pool).await.unwrap();
        assert_eq!(remaining, 0, "{action}");
        let (_, new) = f.claimed("held").await;
        assert_ne!(new.get::<&str, _>("id"), claimed.get::<&str, _>("id"));
        assert!(f.rt.publish(&claimed, &token).await.is_err());
        f.rt.pool.close().await;
    }
}
#[tokio::test]
async fn restart_expires_attempts_but_not_committed_accounts() {
    let f = Fixture::new().await;
    let (done, a) = f.claimed("done").await;
    f.rt.publish(&a, &f.token()).await.unwrap();
    let pending = f.start("pending").await;
    let (_, exchanging) = f.claimed("exchanging").await;
    let next = Runtime::new(
        f.rt.pool.clone(),
        f.rt.key.clone(),
        f.rt.config.clone(),
        RefreshOwner::default(),
    )
    .await
    .unwrap();
    for id in [
        pending["attempt_id"].as_str().unwrap(),
        exchanging.get::<&str, _>("id"),
    ] {
        assert_eq!(
            next.poll("owner", "fixture", id).await.unwrap()["state"],
            "expired"
        );
    }
    assert_eq!(
        next.poll("owner", "fixture", done["attempt_id"].as_str().unwrap())
            .await
            .unwrap()["state"],
        "connected"
    );
    sqlx::query("UPDATE oauth_consent_attempts SET updated_at=0")
        .execute(&f.rt.pool)
        .await
        .unwrap();
    next.sweep().await.unwrap();
    assert_eq!(
        next.account("owner", "fixture", "done").await.unwrap()["state"],
        "connected_unbound"
    );
    f.rt.pool.close().await;
}
#[tokio::test]
async fn deferred_commit_failure_does_not_publish_account_or_connected_attempt() {
    let f = Fixture::new().await;
    let (_, a) = f.claimed("commit").await;
    for sql in [
        "CREATE TABLE consent_parent(id INTEGER PRIMARY KEY)",
        "CREATE TABLE consent_child(id INTEGER REFERENCES consent_parent(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER consent_deferred AFTER INSERT ON oauth_sessions WHEN NEW.kind='controlled_linear_v1' BEGIN INSERT INTO consent_child VALUES(1); END",
    ] {
        f.rt.pool.execute(sql).await.unwrap();
    }
    assert_eq!(
        f.rt.publish(&a, &f.token()).await.unwrap_err().0,
        "commit_unknown"
    );
    assert_eq!(
        f.rt.account("owner", "fixture", "commit").await.unwrap()["state"],
        "absent"
    );
    assert_eq!(
        f.rt.poll("owner", "fixture", a.get("id")).await.unwrap()["state"],
        "exchanging"
    );
    f.rt.pool.close().await;
}
#[tokio::test]
async fn token_optionality_strict_duplicates_and_semantic_secret_screening() {
    let f = Fixture::new().await;
    let p = &f.rt.config.profiles[0];
    let t = token::decode(
        p,
        br#"{"access_token":"escape\\\"token","token_type":"Bearer"}"#,
    )
    .unwrap();
    assert!(t.expiry.is_none() && t.refresh.is_none() && !t.scope_echoed);
    assert!(
        t.screen(&json!({"nested":["echo escape\\\"token"]}))
            .is_err()
    );
    for extra in [
        ",\"refresh_token\":null",
        ",\"expires_in\":0",
        ",\"expires_in\":null",
        ",\"scope\":null",
        ",\"scope\":\"write\"",
        ",\"resource\":\"wrong\"",
        ",\"resource\":null",
        ",\"client_id\":\"wrong\"",
        ",\"client_id\":null",
        ",\"issuer\":\"wrong\"",
        ",\"issuer\":null",
        ",\"iss\":\"wrong\"",
        ",\"iss\":null",
        ",\"expires_in\":31536001",
        ",\"refresh_token\":\"\"",
        ",\"access_token\":\"duplicate\"",
    ] {
        let raw = format!("{{\"access_token\":\"token\",\"token_type\":\"Bearer\"{extra}}}");
        assert!(token::decode(p, raw.as_bytes()).is_err(), "{extra}");
    }
    f.rt.pool.close().await;
}
#[tokio::test]
async fn token_success_refuses_error_members_even_with_valid_credentials() {
    let f = Fixture::new().await;
    let p = &f.rt.config.profiles[0];
    let mut response = json!({"access_token":"synthetic-access","token_type":"Bearer"});
    assert!(token::decode(p, response.to_string().as_bytes()).is_ok());
    for name in ["error", "error_description", "error_uri"] {
        response[name] = Value::Null;
        assert!(
            token::decode(p, response.to_string().as_bytes()).is_err(),
            "{name}"
        );
        response.as_object_mut().unwrap().remove(name);
    }
    f.rt.pool.close().await;
}
#[tokio::test]
async fn callback_rejects_duplicate_and_wrong_state_without_consuming_valid_attempt() {
    let f = Fixture::new().await;
    let v = f.start("safe").await;
    assert!(
        f.rt.claim("wrong", &f.rt.config.profiles[0].issuer, "127.0.0.1:19294")
            .await
            .is_err()
    );
    let url = reqwest::Url::parse(v["authorization_url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    assert!(
        f.rt.claim(&state, "https://wrong", "127.0.0.1:19294")
            .await
            .is_err()
    );
    let a =
        f.rt.claim(&state, &f.rt.config.profiles[0].issuer, "127.0.0.1:19294")
            .await
            .unwrap();
    assert!(
        f.rt.claim(&state, &f.rt.config.profiles[0].issuer, "127.0.0.1:19294")
            .await
            .is_err()
    );
    assert_eq!(a.get::<&str, _>("state"), "exchanging");
    f.rt.pool.close().await;
}

#[tokio::test]
async fn wrong_key_refuses_consent_startup_without_mutating_committed_custody() {
    let f = Fixture::new().await;
    let (_, a) = f.claimed("sealed").await;
    f.rt.publish(&a, &f.token()).await.unwrap();
    let before: Vec<u8> = sqlx::query_scalar(
        "SELECT access_token_ciphertext FROM oauth_sessions WHERE name='fixture'",
    )
    .fetch_one(&f.rt.pool)
    .await
    .unwrap();
    let result = Runtime::new(
        f.rt.pool.clone(),
        SealingKey::generate().unwrap(),
        f.rt.config.clone(),
        RefreshOwner::default(),
    )
    .await;
    assert!(
        matches!(result, Err(Error("sealing_failed"))),
        "a wrong key cannot admit new consent alongside existing custody"
    );
    let after: Vec<u8> = sqlx::query_scalar(
        "SELECT access_token_ciphertext FROM oauth_sessions WHERE name='fixture'",
    )
    .fetch_one(&f.rt.pool)
    .await
    .unwrap();
    assert_eq!(before, after);
    f.rt.pool.close().await;
}

#[tokio::test]
async fn finite_attempt_capacity_expires_and_evicts_only_terminal_records() {
    let f = Fixture::new().await;
    for i in 0..8 {
        f.start(&format!("active{i}")).await;
    }
    let request = Start {
        session_label: "overflow".into(),
        auth_profile_id: "fixture".into(),
        client_generation: 1,
        requested_scopes: vec!["read".into()],
        redirect_profile_id: "loopback".into(),
        expected_config_revision: 1,
    };
    assert_eq!(
        f.rt.start("owner", "fixture", &request)
            .await
            .unwrap_err()
            .0,
        "capacity"
    );
    sqlx::query("UPDATE oauth_consent_attempts SET deadline=0")
        .execute(&f.rt.pool)
        .await
        .unwrap();
    for i in 0..132 {
        let result = f.start(&format!("terminal{i}")).await;
        f.rt.cancel("owner", "fixture", result["attempt_id"].as_str().unwrap())
            .await
            .unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_consent_attempts")
        .fetch_one(&f.rt.pool)
        .await
        .unwrap();
    assert_eq!(count, 128);
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM oauth_consent_attempts WHERE verifier_ct IS NOT NULL OR quarantine_ct IS NOT NULL OR state_hash IS NOT NULL").fetch_one(&f.rt.pool).await.unwrap(),0);
    f.rt.pool.close().await;
}
#[tokio::test]
async fn callback_parser_bounds_and_profile_fail_closed() {
    let f = Fixture::new().await;
    let state = "a".repeat(43);
    let base =
        format!("/oauth/callback?state={state}&iss=https%3A%2F%2F127.0.0.1%3A19293&code=code");
    let request = |uri: &str, host: &str| {
        axum::http::Request::builder()
            .uri(uri)
            .header("host", host)
            .body(axum::body::Body::empty())
            .unwrap()
    };
    assert!(server::parameters(&f.rt, &request(&base, "127.0.0.1:19294")).is_ok());
    for uri in [
        format!("{base}&code=other"),
        format!("{base}&%73tate={state}"),
        format!("{base}&error=denied"),
        format!("{base}&unknown=%ZZ"),
        format!("{base}&unknown=%FF"),
        format!("{base}&unknown={}", "x".repeat(8192)),
        format!(
            "{base}{}",
            (0..15).map(|i| format!("&k{i}=v")).collect::<String>()
        ),
    ] {
        assert!(server::parameters(&f.rt, &request(&uri, "127.0.0.1:19294")).is_err());
    }
    assert!(server::parameters(&f.rt, &request(&base, "localhost:19294")).is_err());
    let mut forwarded = request(&base, "127.0.0.1:19294");
    forwarded
        .headers_mut()
        .insert("forwarded", "host=127.0.0.1".parse().unwrap());
    assert!(server::parameters(&f.rt, &forwarded).is_err());
    for endpoint in [
        "https://localhost:19293/token",
        "http://127.0.0.1:19293/token",
        "https://127.0.0.1:0/token",
        "https://user@127.0.0.1:19293/token",
        "https://127.0.0.1:19293/token?extra=1",
    ] {
        let mut c = f.rt.config.clone();
        c.profiles[0].token_endpoint = endpoint.into();
        assert!(c.validate().is_err());
    }
    f.rt.pool.close().await;
}

#[tokio::test]
async fn callback_exit_hook_runs_when_the_listener_task_ends() {
    // Consent requires a fixed, nonzero callback port matching its redirect URI.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = free.local_addr().unwrap();
    drop(free);
    let f = Fixture::with_callback(address).await;
    let supervisor = server::Supervisor::default();
    let (fired, ended) = tokio::sync::oneshot::channel();
    supervisor
        .start(f.rt.clone(), move || {
            let _ = fired.send(());
        })
        .await
        .unwrap();
    supervisor.stop_join().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), ended)
        .await
        .expect("exit hook ran")
        .unwrap();
}

#[tokio::test]
async fn failed_callback_start_never_runs_the_exit_hook() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let f = Fixture::with_callback(held.local_addr().unwrap()).await;
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = fired.clone();
    let result = server::Supervisor::default()
        .start(f.rt.clone(), move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
    assert_eq!(result.err().map(|e| e.0), Some("callback_bind_failed"));
    assert!(!fired.load(std::sync::atomic::Ordering::SeqCst));
}

#[path = "refresh/tests.rs"]
mod refresh_cases;
