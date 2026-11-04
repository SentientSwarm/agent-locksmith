use super::{fixture::Fixture, process};
use serde_json::{Value, json};

pub fn document(f: &Fixture, revision: u32) -> std::path::PathBuf {
    let mut d: Value =
        serde_json::from_str(include_str!("../../definitions/customer.example.json")).unwrap();
    d["revision"] = json!(revision);
    let path = f.path().join(format!("definition-{revision}.json"));
    std::fs::write(&path, d.to_string()).unwrap();
    path
}
pub fn import(f: &Fixture, revision: u32) -> Value {
    f.op(&[
        "integration",
        "import",
        "--file",
        document(f, revision).to_str().unwrap(),
    ])
}
pub fn create(f: &Fixture, endpoint: &str) -> Value {
    f.op(&[
        "tool",
        "from-definition",
        "customer",
        "--definition",
        "local.customer",
        "--revision",
        "1",
        "--auth-profile",
        "none",
        "--upstream",
        endpoint,
        "--allow-private-destination",
    ])
}
pub async fn pool(f: &Fixture) -> sqlx::SqlitePool {
    sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(f.path().join("state.db"))
            .read_only(true),
    )
    .await
    .unwrap()
}
pub async fn authority(f: &Fixture) -> Vec<Vec<String>> {
    let pool = pool(f).await;
    let mut result = Vec::new();
    for q in [
        "SELECT json_array(id,public_id,tool_allowlist,tool_denylist,grants_reviewed,expires_at,revoked_at,mcp_epoch) FROM agents ORDER BY id",
        "SELECT json_array(agent_id,registration,auth_spec,created_at,updated_at) FROM agent_credential_overrides ORDER BY agent_id,registration",
        "SELECT json_array(public_id,scope,grants_reviewed,revoked_at) FROM bootstrap_tokens ORDER BY public_id",
        "SELECT json_array(name,session_label,incarnation,token_version) FROM oauth_sessions ORDER BY name,session_label",
        "SELECT json_array(secret_ref,set_at,tombstoned_at) FROM credential_secrets ORDER BY secret_ref",
    ] {
        result.push(sqlx::query_scalar(q).fetch_all(&pool).await.unwrap());
    }
    pool.close().await;
    result
}
pub fn refused_cli(f: &Fixture, args: &[&str], code: i32) {
    let out = process::run(f.command(args));
    assert_eq!(out.status.code(), Some(code));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("definition-secret-canary"));
}
pub async fn raw(f: &Fixture, token: &str, path: &str, bytes: Vec<u8>) -> (u16, bytes::Bytes) {
    agent_locksmith::admin::uds_client::UdsClient::new(f.path().join("admin.sock"))
        .request(
            "PUT",
            path,
            &[
                ("authorization", &format!("Bearer {token}")),
                ("content-type", "application/json"),
            ],
            Some(bytes),
        )
        .await
        .unwrap()
}
