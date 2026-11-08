use super::{fixture::Fixture, flow, process, upgrade_http};
use serde_json::Value;

async fn query(f: &Fixture, sql: &str) -> String {
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db")),
    )
    .await
    .unwrap();
    let result = sqlx::query_scalar(sql).fetch_one(&pool).await.unwrap();
    pool.close().await;
    result
}
async fn authority(f: &Fixture) -> String {
    query(f, "SELECT json_group_array(json_array(agent_id,registration,auth_spec)) FROM agent_credential_overrides ORDER BY agent_id,registration").await
}
pub async fn exercise() {
    let prior = std::env::var("LOCKSMITH_PREPARATION_PRIOR_DAEMON").unwrap();
    let mut f = Fixture::new();
    // The prior binary logs its configured address, so it cannot report an
    // OS-assigned port.
    f.use_stable_port();
    f.start_with_key(&prior, Some(upgrade_http::KEY)).await;
    let agent = f.enroll("upgrade", "https://example.com/mcp");
    let (_http_receiver, http_agent) = upgrade_http::setup(&f).await;
    assert_eq!(
        query(
            &f,
            "SELECT CAST(max(version) AS TEXT) FROM _sqlx_migrations"
        )
        .await,
        "13"
    );
    let (before, custody) = (authority(&f).await, sealed(&f).await);
    f.stop();
    f.start_with_key(process::DAEMON, Some(upgrade_http::KEY))
        .await;
    verify(&f, &agent, &before).await;
    assert_eq!(sealed(&f).await, custody);
    upgrade_http::allowed(&f, &http_agent).await;
    f.stop();
    refused(&f, &prior);
    f.start_with_key(process::DAEMON, Some(upgrade_http::KEY))
        .await;
    verify(&f, &agent, &before).await;
    assert_eq!(sealed(&f).await, custody);
    upgrade_http::allowed(&f, &http_agent).await;
    f.stop();
}
async fn sealed(f: &Fixture) -> String {
    query(f, "SELECT json_group_array(json_array(secret_ref,hex(sealed_value),hex(nonce),tombstoned_at)) FROM credential_secrets ORDER BY secret_ref").await
}
async fn verify(f: &Fixture, agent: &Value, before: &str) {
    assert_eq!(
        query(f, "SELECT CAST(max(version) AS TEXT) FROM _sqlx_migrations").await,
        "19"
    );
    assert_eq!(authority(f).await, before);
    let snapshot = flow::show(f, agent["public_id"].as_str().unwrap());
    assert_eq!(snapshot["observation"], Value::Null);
    assert_eq!(snapshot["grant_revision"], Value::Null);
    assert_eq!(snapshot["tools"], serde_json::json!([]));
    assert_eq!(snapshot["callable"], false);
    for table in [
        "native_observations",
        "native_reviews",
        "native_grant_sets",
        "native_tool_grants",
    ] {
        assert_eq!(
            query(f, &format!("SELECT CAST(count(*) AS TEXT) FROM {table}")).await,
            "0"
        );
    }
}
fn refused(f: &Fixture, prior: &str) {
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
    assert!(message.contains("migration 14") && message.contains("missing"));
    assert!(!f.path().join("admin.sock").exists());
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.port)).is_err());
}
