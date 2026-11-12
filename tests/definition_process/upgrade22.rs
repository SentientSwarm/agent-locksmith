// Adapted retained ciphertext/sequence test for actual schema 21 -> 22.
use super::{fixture::Fixture, process, support};

pub async fn exercise() {
    let prior = std::env::var("LOCKSMITH_CONTRACT_PRIOR_DAEMON").unwrap();
    for keep_row in [true, false] {
        let mut f = Fixture::new();
        f.start(&prior).await;
        f.enroll("existing", "https://example.com/mcp");
        support::import(&f, 1);
        support::create(&f, "https://example.com/customer");
        assert_eq!(version(&f).await, 21);
        f.stop();
        custody(&f, keep_row).await;
        let before = snapshot(&f).await;
        f.start(process::DAEMON).await;
        assert_eq!(version(&f).await, 26);
        assert_eq!(snapshot(&f).await, before);
        f.stop();
        refuses_prior(&f, &prior);
        f.start(process::DAEMON).await;
        assert_eq!(snapshot(&f).await, before);
        assert_eq!(f.op(&["tool", "get", "customer"])["disabled"], true);
        f.stop();
    }
}

async fn version(f: &Fixture) -> i64 {
    let pool = support::pool(f).await;
    let v = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;
    v
}

async fn custody(f: &Fixture, keep_row: bool) {
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db")),
    )
    .await
    .unwrap();
    let key = agent_locksmith::oauth::SealingKey::generate().unwrap();
    let (ct, nonce) = key.seal(b"invented-migration-value").unwrap();
    sqlx::query("INSERT INTO oauth_sessions(incarnation,name,refresh_token_ciphertext,refresh_token_nonce,created_at,updated_at) VALUES(7,'legacy',?,?,1,1),(99,'deleted',?,?,1,1)")
        .bind(&ct).bind(&nonce).bind(&ct).bind(&nonce).execute(&pool).await.unwrap();
    let sql = if keep_row {
        "DELETE FROM oauth_sessions WHERE incarnation=99"
    } else {
        "DELETE FROM oauth_sessions"
    };
    sqlx::query(sql).execute(&pool).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT seq FROM sqlite_sequence WHERE name='oauth_sessions'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        99
    );
    pool.close().await;
}

async fn snapshot(f: &Fixture) -> Vec<Vec<String>> {
    let mut values = support::authority(f).await;
    let pool = support::pool(f).await;
    for sql in [
        "SELECT json_array(name,auth_json,mcp_json,disabled,upstream) FROM registrations ORDER BY name",
        "SELECT json_array(id,revision,digest,canonical_json) FROM integration_definitions ORDER BY id",
        "SELECT json_array(name,instance_id,revision) FROM registration_instances ORDER BY name",
        "SELECT json_array(incarnation,name,kind,hex(refresh_token_ciphertext),hex(refresh_token_nonce),hex(access_token_ciphertext),hex(access_token_nonce),token_version,refresh_pending,access_token_expires_at) FROM oauth_sessions ORDER BY incarnation",
        "SELECT json_array(name,seq) FROM sqlite_sequence WHERE name='oauth_sessions' ORDER BY name",
    ] {
        values.push(sqlx::query_scalar(sql).fetch_all(&pool).await.unwrap());
    }
    pool.close().await;
    values
}

fn refuses_prior(f: &Fixture, prior: &str) {
    let _ = std::fs::remove_file(f.path().join("admin.sock"));
    let mut command = process::command(prior);
    command.arg("--config").arg(f.path().join("config.yaml"));
    let out = process::run(command);
    assert!(!out.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(message.contains("migration 22") && message.contains("missing"));
    assert!(!f.path().join("admin.sock").exists());
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.port)).is_err());
}
