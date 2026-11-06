use super::*;
async fn setup() -> (Fixture, Twin, u16, Value) {
    let mut f = Fixture::new();
    std::fs::write(f.path().join("refresh-enabled"), "fixture").unwrap();
    let t = Twin::start(&f);
    let port = configure(&f, &t);
    start(&mut f).await;
    registration(&f, &t, port).await;
    let created = connect(&f, "refresh");
    assert_eq!(
        f.http
            .get(callback(&t, port, &created))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    (f, t, port, created)
}
fn status(f: &Fixture) -> Value {
    f.op(&["oauth", "account-status", "fixture", "--label", "refresh"])
}
fn refresh(f: &Fixture, revision: &str) -> std::process::Command {
    f.command(&[
        "oauth",
        "refresh",
        "fixture",
        "--label",
        "refresh",
        "--if-match",
        revision,
    ])
}
async fn api(f: &Fixture, revision: Option<&str>, body: Option<Vec<u8>>) -> (u16, Value) {
    let auth = format!("Bearer {}", f.operator);
    let mut headers = vec![("authorization", auth.as_str())];
    if let Some(rev) = revision {
        headers.push(("if-match", rev));
    }
    let (status, bytes) = UdsClient::new(f.path().join("admin.sock"))
        .request(
            "POST",
            "/admin/operator/tools/fixture/oauth/accounts/refresh/refresh",
            &headers,
            body,
        )
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
pub async fn journey() {
    let (mut f, t, port, created) = setup().await;
    let before = status(&f);
    let agent = f.op(&[
        "agent",
        "register",
        "--name",
        "refresh-preselected",
        "--allowlist",
        "fixture",
    ]);
    let selected = json!({"kind":"oauth_pkce","client_id":"fixture-client","redirect_uri":format!("https://127.0.0.1:{port}/oauth/callback"),"scopes":["read"],"auth_url":t.url("/authorize"),"token_url":t.url("/token"),"session_label":"refresh"});
    assert_eq!(
        request(
            &f,
            "PUT",
            &format!(
                "/admin/operator/agents/{}/credentials/fixture",
                agent["public_id"].as_str().unwrap()
            ),
            Some(json!({"auth_spec":selected}))
        )
        .await
        .0,
        200
    );
    let baseline = counts(&f);
    assert_eq!(api(&f, None, None).await.0, 428);
    assert_eq!(
        api(
            &f,
            Some(before["revision"].as_str().unwrap()),
            Some(b"{}".to_vec())
        )
        .await
        .0,
        400
    );
    assert_eq!(counts(&f), baseline);
    for omitted in [false, true] {
        if omitted {
            std::fs::write(f.path().join("fail-delete"), "fixture").unwrap();
            std::fs::write(f.path().join("omit-refresh"), "fixture").unwrap();
        }
        let current = status(&f);
        let output = process::run(refresh(&f, current["revision"].as_str().unwrap()));
        assert!(
            output.status.success(),
            "refresh stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["refresh"]["outcome"], "committed");
        assert_eq!(result["refresh"]["finalization"], "committed");
        assert_eq!(
            result["refresh"]["cleanup"],
            if omitted {
                "attempt_failed"
            } else {
                "attempted_helper_accepted"
            }
        );
        let receiver_before = counts(&f);
        assert_eq!(
            f.http
                .get(f.url("/api/fixture/check"))
                .bearer_auth(agent["token"].as_str().unwrap())
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        assert_eq!(counts(&f), receiver_before);
        assert_eq!(f.op(&["oauth", "list"]), json!([]));
        assert_eq!(result["account_generation"], before["account_generation"]);
        assert_eq!(result["token_expires_at"], Value::Null);
        assert_eq!(result["granted_scope"], Value::Null);
        assert_eq!(
            api(&f, Some(current["revision"].as_str().unwrap()), None)
                .await
                .0,
            409
        );
    }
    let current = status(&f);
    assert_eq!(current["token_version"], 4);
    assert_eq!(counts(&f)["refresh"], 2);
    assert_eq!(counts(&f)["consumed"], 2);
    assert_eq!(counts(&f)["issued"], 2);
    assert_eq!(counts(&f)["workspace"], 3);
    assert_eq!(counts(&f)["user"], 3);
    assert_eq!(counts(&f)["other"], 0);
    f.op(&[
        "oauth",
        "cancel",
        "fixture",
        created["attempt_id"].as_str().unwrap(),
    ]);
    f.stop();
    start(&mut f).await;
    assert_eq!(status(&f), current);
    assert_eq!(counts(&f)["refresh"], 2);
    std::fs::write(f.path().join("invalid-grant"), "fixture").unwrap();
    let failed = api(&f, Some(current["revision"].as_str().unwrap()), None).await;
    assert_eq!(failed.0, 400);
    assert_eq!(failed.1["refresh"]["safe_reason"], "refresh_invalid_grant");
    let pending = status(&f);
    assert_eq!(pending["state"], "reconnect_required");
    assert_eq!(pending["refresh_pending"], true);
    assert_eq!(
        api(&f, Some(pending["revision"].as_str().unwrap()), None)
            .await
            .0,
        409
    );
    assert_eq!(counts(&f)["refresh"], 3);
    f.op(&[
        "oauth",
        "disconnect",
        "fixture",
        "--label",
        "refresh",
        "--if-match",
        pending["revision"].as_str().unwrap(),
    ]);
    let again = connect(&f, "refresh");
    assert_eq!(
        f.http
            .get(callback(&t, port, &again))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_ne!(
        status(&f)["account_generation"],
        before["account_generation"]
    );
    println!(
        "refresh rotation/omission,2 consumptions,3 renewal arrivals including explicit invalid_grant; status zero I/O; restart no replay; explicit fresh consent; counts={}",
        counts(&f)
    );
    f.stop();
    t.stop();
}
pub async fn refusals() {
    for mode in [
        "token-error-member",
        "wrong-user",
        "schema-query-const",
        "token-metadata",
        "echo-old-refresh",
    ] {
        let (mut f, t, _, _) = setup().await;
        let before = status(&f);
        std::fs::write(
            f.path().join(mode),
            if mode == "token-metadata" {
                "{\"expires_in\":null}"
            } else {
                "fixture"
            },
        )
        .unwrap();
        let (code, result) = api(&f, Some(before["revision"].as_str().unwrap()), None).await;
        assert_eq!(code, 400, "{mode}: {result}");
        let after = status(&f);
        assert_eq!(after["refresh_pending"], true);
        assert_eq!(after["token_version"], 1);
        assert_eq!(counts(&f)["refresh"], 1);
        assert_eq!(counts(&f)["consumed"], 1);
        assert_eq!(counts(&f)["other"], 0);
        if mode != "wrong-user" {
            assert_eq!(counts(&f)["workspace"], 1);
            assert_eq!(counts(&f)["user"], 1);
        }
        f.stop();
        start(&mut f).await;
        assert_eq!(status(&f), after);
        assert_eq!(counts(&f)["refresh"], 1);
        println!(
            "refresh refusal={mode} diagnostic={} counts={}",
            result["refresh"],
            counts(&f)
        );
        f.stop();
        t.stop();
    }
}
pub async fn late() {
    for mode in ["disconnect", "crash"] {
        let (mut f, t, port, _) = setup().await;
        let before = status(&f);
        std::fs::write(f.path().join("hold-refresh"), "held").unwrap();
        let mut child = process::Guard(
            refresh(&f, before["revision"].as_str().unwrap())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        arrived(&f, "refresh").await;
        let pending = status(&f);
        assert_eq!(pending["refresh_pending"], true);
        assert_eq!(
            api(&f, Some(before["revision"].as_str().unwrap()), None)
                .await
                .0,
            409
        );
        assert_eq!(counts(&f)["refresh"], 1);
        assert_eq!(counts(&f)["consumed"], 1);
        if mode == "crash" {
            let mut daemon = f.daemon.take().unwrap();
            daemon.0.kill().unwrap();
            daemon.0.wait().unwrap();
        } else {
            f.op(&[
                "oauth",
                "disconnect",
                "fixture",
                "--label",
                "refresh",
                "--if-match",
                pending["revision"].as_str().unwrap(),
            ]);
            let created = connect(&f, "refresh");
            assert_eq!(
                f.http
                    .get(callback(&t, port, &created))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                200
            );
        }
        std::fs::write(f.path().join("release-refresh"), "release").unwrap();
        wait_path(&f.path().join("finished-refresh")).await;
        assert!(!process::wait(&mut child.0).success());
        if mode == "crash" {
            start(&mut f).await;
            assert_eq!(status(&f), pending);
        } else {
            assert_ne!(
                status(&f)["account_generation"],
                before["account_generation"]
            );
            assert_eq!(status(&f)["refresh_pending"], false);
        }
        assert_eq!(counts(&f)["refresh"], 1);
        assert_eq!(counts(&f)["workspace"], if mode == "crash" { 1 } else { 2 });
        println!(
            "refresh held consumption={mode}; one arrival/consumption, late publication refused; counts={}",
            counts(&f)
        );
        f.stop();
        t.stop();
    }
}

pub async fn ownership() {
    use sqlx::Row;
    for mode in ["normal", "forced", "startup"] {
        let (mut f, t, _, _) = setup().await;
        let before = status(&f);
        f.stop();
        if mode == "startup" {
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(f.path().join("startup-cert"))
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let log = std::fs::File::create(f.path().join("embedding.log")).unwrap();
        let mut c = process::command(std::env::current_exe().unwrap().to_str().unwrap());
        c.args([
            "--exact",
            "embedded_consent_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("CONSENT_EMBEDDED", f.path())
        .env("CONTROLLED_REFRESH_OWNER_MODE", mode)
        .env("LOCKSMITH_OAUTH_SEALING_KEY", KEY)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
        let mut worker = process::Guard(c.spawn().unwrap());
        wait_path(&f.path().join("embedded-ready")).await;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(f.path().join("state.db.daemon.lock"))
            .unwrap();
        assert!(lock.try_lock().is_err());
        std::fs::write(f.path().join("hold-refresh"), "held").unwrap();
        let mut request = process::Guard(
            refresh(&f, before["revision"].as_str().unwrap())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        arrived(&f, "refresh").await;
        let pending = status(&f);
        assert_eq!(pending["refresh_pending"], true);
        if mode == "startup" {
            // The admin HTTPS listener fails mid-flight and stops the daemon.
            std::fs::write(f.path().join("startup-cert"), "invalid certificate fixture").unwrap();
        } else {
            std::fs::write(f.path().join("shutdown"), "stop").unwrap();
        }
        wait_path(&f.path().join("returned")).await;
        assert!(worker.0.try_wait().unwrap().is_none());
        lock.try_lock().unwrap();
        let pool = agent_locksmith::migrations::open_and_migrate(&f.path().join("state.db"))
            .await
            .unwrap();
        let row=sqlx::query("SELECT token_version,refresh_pending,access_token_ciphertext,refresh_token_ciphertext FROM oauth_sessions WHERE session_label='refresh'").fetch_one(&pool).await.unwrap();
        let snapshot = (
            row.get::<i64, _>("token_version"),
            row.get::<bool, _>("refresh_pending"),
            row.get::<Vec<u8>, _>("access_token_ciphertext"),
            row.get::<Vec<u8>, _>("refresh_token_ciphertext"),
        );
        std::fs::write(f.path().join("release-refresh"), "release").unwrap();
        wait_path(&f.path().join("finished-refresh")).await;
        assert!(!process::wait(&mut request.0).success());
        let row=sqlx::query("SELECT token_version,refresh_pending,access_token_ciphertext,refresh_token_ciphertext FROM oauth_sessions WHERE session_label='refresh'").fetch_one(&pool).await.unwrap();
        assert_eq!(
            snapshot,
            (
                row.get::<i64, _>("token_version"),
                row.get::<bool, _>("refresh_pending"),
                row.get::<Vec<u8>, _>("access_token_ciphertext"),
                row.get::<Vec<u8>, _>("refresh_token_ciphertext")
            )
        );
        assert_eq!(counts(&f)["refresh"], 1);
        assert_eq!(counts(&f)["consumed"], 1);
        assert_eq!(counts(&f)["workspace"], 1);
        pool.close().await;
        drop(lock);
        std::fs::write(f.path().join("finish"), "finish").unwrap();
        assert!(process::wait(&mut worker.0).success());
        t.stop();
        println!(
            "refresh owner {mode}: embedding return alive, direct canonical lock without successor, late response no publication, all joined"
        );
    }
}

pub async fn upgrade() {
    use sqlx::Row;
    let prior = std::env::var("CONTROLLED_PRIOR_DAEMON").expect("retained prior binary");
    let cli = std::env::var("CONTROLLED_PRIOR_CLI").expect("retained prior CLI");
    let prior_schema = std::env::var("CONTROLLED_PRIOR_SCHEMA")
        .ok()
        .map(|v| v.parse::<i64>().unwrap())
        .unwrap_or(15);
    let mut f = Fixture::new();
    std::fs::write(f.path().join("refresh-enabled"), "fixture").unwrap();
    let t = Twin::start(&f);
    let port = configure(&f, &t);
    start_binary(&mut f, &prior).await;
    registration(&f, &t, port).await;
    let created = connect(&f, "refresh");
    assert_eq!(
        f.http
            .get(callback(&t, port, &created))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let mut old_cli = process::command(&cli);
    old_cli
        .arg("--socket")
        .arg(f.path().join("admin.sock"))
        .args([
            "--format",
            "json",
            "oauth",
            "account-status",
            "fixture",
            "--label",
            "refresh",
        ])
        .env("LOCKSMITH_OP_TOKEN", &f.operator);
    assert_eq!(
        process::json(process::run(old_cli))["state"],
        "connected_unbound"
    );
    f.stop();
    let pool =
        sqlx::SqlitePool::connect(&format!("sqlite://{}", f.path().join("state.db").display()))
            .await
            .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        prior_schema
    );
    let rows = sqlx::query("SELECT * FROM oauth_sessions")
        .fetch_all(&pool)
        .await
        .unwrap();
    let before = rows
        .iter()
        .map(|r| {
            (
                r.get::<i64, _>("incarnation"),
                r.get::<i64, _>("token_version"),
                r.get::<Vec<u8>, _>("access_token_ciphertext"),
                r.get::<Vec<u8>, _>("refresh_token_ciphertext"),
                r.get::<String, _>("owner_id"),
                r.get::<String, _>("profile_digest"),
                r.get::<Option<i64>, _>("access_token_expires_at"),
            )
        })
        .collect::<Vec<_>>();
    pool.close().await;
    start(&mut f).await;
    let current = status(&f);
    assert_eq!(current["token_version"], 0);
    f.stop();
    let pool =
        sqlx::SqlitePool::connect(&format!("sqlite://{}", f.path().join("state.db").display()))
            .await
            .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        17
    );
    let rows = sqlx::query("SELECT * FROM oauth_sessions")
        .fetch_all(&pool)
        .await
        .unwrap();
    let after = rows
        .iter()
        .map(|r| {
            (
                r.get::<i64, _>("incarnation"),
                r.get::<i64, _>("token_version"),
                r.get::<Vec<u8>, _>("access_token_ciphertext"),
                r.get::<Vec<u8>, _>("refresh_token_ciphertext"),
                r.get::<String, _>("owner_id"),
                r.get::<String, _>("profile_digest"),
                r.get::<Option<i64>, _>("access_token_expires_at"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(before, after);
    pool.close().await;
    if f.path().join("admin.sock").exists() {
        std::fs::remove_file(f.path().join("admin.sock")).unwrap();
    }
    let mut command = process::command(&prior);
    command
        .arg("--config")
        .arg(f.path().join("config.yaml"))
        .env("LOCKSMITH_OAUTH_SEALING_KEY", KEY);
    let refused = process::run(command);
    assert!(!refused.status.success());
    assert!(!f.path().join("admin.sock").exists());
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.port)).is_err());
    start(&mut f).await;
    assert_eq!(status(&f), current);
    let output = process::run(refresh(&f, current["revision"].as_str().unwrap()));
    assert!(output.status.success());
    assert_eq!(counts(&f)["refresh"], 1);
    assert_eq!(counts(&f)["consumed"], 1);
    f.stop();
    t.stop();
    println!(
        "actual schema-{prior_schema} CLI+daemon connected account -> schema-17 unchanged custody -> prior refusal before listeners -> new reopen/manual refresh; joined"
    );
}
