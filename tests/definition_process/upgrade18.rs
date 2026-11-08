use super::{fixture::Fixture, process, support};
use serde_json::{Value, json};
use sqlx::Row;
async fn snapshot(f: &Fixture) -> Value {
    let pool = support::pool(f).await;
    let mut v = json!({});
    for (name, q) in [
        (
            "authority",
            "SELECT json_array(id,public_id,tool_allowlist,tool_denylist,grants_reviewed,expires_at,revoked_at,mcp_epoch) FROM agents ORDER BY id",
        ),
        (
            "bindings",
            "SELECT json_array(agent_id,registration,auth_spec,created_at,updated_at) FROM agent_credential_overrides ORDER BY agent_id,registration",
        ),
        (
            "registrations",
            "SELECT json_array(name,kind,auth_json,mcp_json,disabled,upstream) FROM registrations ORDER BY name",
        ),
        (
            "definitions",
            "SELECT json_array(id,revision,digest,canonical_json) FROM integration_definitions ORDER BY id",
        ),
        (
            "custody",
            "SELECT json_array(incarnation,name,kind,owner_id,profile_id,profile_digest,hex(refresh_token_ciphertext),hex(refresh_token_nonce),hex(access_token_ciphertext),hex(access_token_nonce),access_token_expires_at,scope,degraded,created_at,updated_at,token_version,refresh_pending,workspace_id,user_id,scope_echoed) FROM oauth_sessions ORDER BY incarnation",
        ),
        (
            "highwater",
            "SELECT json_array(name,seq) FROM sqlite_sequence WHERE name='oauth_sessions'",
        ),
    ] {
        v[name] = json!(
            sqlx::query_scalar::<_, String>(q)
                .fetch_all(&pool)
                .await
                .unwrap()
        );
    }
    pool.close().await;
    v
}
pub async fn exercise() {
    let prior = std::env::var("LOCKSMITH_DEFINITION_PRIOR_DAEMON").unwrap();
    let cli = std::env::var("LOCKSMITH_DEFINITION_PRIOR_CLI").unwrap();
    let mut f = Fixture::new();
    f.start(&prior).await;
    let mut c = process::command(&cli);
    c.arg("--build-info");
    let identity = process::json(process::run(c));
    // The retained prior must be the build the caller names, e.g. the
    // schema-17 controlled native accounts head in CI.
    let expected = std::env::var("LOCKSMITH_DEFINITION_PRIOR_REVISION").unwrap();
    let revision = identity["build"]["revision"].as_str().unwrap();
    assert!(
        revision.starts_with(&expected) && identity["build"]["source_state"] == "clean",
        "prior binary identity"
    );
    let mut c = process::command(&cli);
    c.arg("--socket")
        .arg(f.path().join("admin.sock"))
        .args([
            "--format",
            "json",
            "tool",
            "put",
            "http",
            "--upstream",
            "https://example.com",
            "--auth",
            "none",
        ])
        .env("LOCKSMITH_OP_TOKEN", &f.operator);
    assert!(process::run(c).status.success());
    let a = f.enroll("existing", "https://example.com/mcp");
    support::import(&f, 1);
    support::create(&f, "https://example.com/customer");
    f.op(&["agent", "revoke", a["public_id"].as_str().unwrap()]);
    f.stop();
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db")),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        17
    );
    let key = agent_locksmith::oauth::SealingKey::from_b64(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .unwrap();
    let (ct, n) = key.seal(b"synthetic-refresh").unwrap();
    sqlx::query("INSERT INTO oauth_sessions(incarnation,name,refresh_token_ciphertext,refresh_token_nonce,created_at,updated_at) VALUES(7,'legacy',?,?,1,1),(99,'deleted',?,?,1,1)").bind(&ct).bind(&n).bind(&ct).bind(&n).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM oauth_sessions WHERE incarnation=99")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO oauth_sessions(name,session_label,kind,owner_id,profile_id,profile_digest,workspace_id,user_id,access_token_ciphertext,access_token_nonce,created_at,updated_at) VALUES('controlled','x','controlled_linear_v1','fixture-owner','fixture-profile','fixture-digest','fixture-workspace','fixture-user',?,?,1,1)").bind(&ct).bind(&n).execute(&pool).await.unwrap();
    pool.close().await;
    let before = snapshot(&f).await;
    f.start(process::DAEMON).await;
    assert_eq!(snapshot(&f).await, before);
    let pool = support::pool(&f).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap(),
        22
    );
    pool.close().await;
    assert_eq!(
        f.op(&["tool", "get", "customer"])["definition_control"]["phase"],
        "disabled"
    );
    f.stop();
    let _ = std::fs::remove_file(f.path().join("admin.sock"));
    let mut c = process::command(&prior);
    c.arg("--config").arg(f.path().join("config.yaml"));
    let out = process::run(c);
    assert!(!out.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(message.contains("migration 18") && message.contains("missing"));
    assert!(!f.path().join("admin.sock").exists());
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.port)).is_err());
    f.start(process::DAEMON).await;
    assert_eq!(snapshot(&f).await, before);
    f.stop();
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db")),
    )
    .await
    .unwrap();
    let row=sqlx::query("INSERT INTO oauth_sessions(name,refresh_token_ciphertext,refresh_token_nonce,created_at,updated_at) VALUES('fresh',?,?,1,1) RETURNING incarnation").bind(&ct).bind(&n).fetch_one(&pool).await.unwrap();
    assert!(row.get::<i64, _>("incarnation") > 100);
    pool.close().await;
    println!(
        "actual schema-17 -> 22: exact pins/manual HTTP/native/revocation/sealed legacy+controlled/highwater preserved; old whole daemon refuses before all listeners; successor reopens"
    );
}
