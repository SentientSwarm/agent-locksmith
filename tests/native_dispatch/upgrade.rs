use super::{calls, discovery, fixture::Fixture, flow, process, receiver, wire};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires accepted A binary via LOCKSMITH_DISPATCH_PRIOR_DAEMON"]
async fn schema14_authority_survives_a_b_a_b_without_migration() {
    let prior = std::env::var("LOCKSMITH_DISPATCH_PRIOR_DAEMON").unwrap();
    let mut f = Fixture::new();
    receiver::configure(&f);
    let receiver = receiver::Receiver::start(&f);
    f.start(&prior).await;
    let a = f.enroll(
        "upgrade",
        &format!("https://localhost:{}/mcp", receiver.port),
    );
    discovery::grant(&f, a["public_id"].as_str().unwrap());
    let authority = authority(&f).await;
    f.stop();
    current(&mut f, &a, &authority).await;
    f.start(&prior).await;
    assert_eq!(self::authority(&f).await, authority);
    let session = wire::open(&f, a["token"].as_str().unwrap()).await;
    assert_eq!(
        discovery::list(&f, a["token"].as_str().unwrap(), &session, 1).await["result"]["tools"],
        json!([])
    );
    assert!(calls::call(&f, &a, &session, 2, json!({})).await["error"].is_object());
    assert_eq!(calls::effects(&f).len(), 1);
    f.stop();
    current(&mut f, &a, &authority).await;
    assert_eq!(calls::effects(&f).len(), 2);
    receiver.stop();
}

async fn current(f: &mut Fixture, a: &Value, expected: &Value) {
    f.start(process::DAEMON).await;
    assert_eq!(&authority(f).await, expected);
    let id = a["public_id"].as_str().unwrap();
    assert_eq!(
        flow::show(f, id)["callable"],
        false,
        "restart needs re-observation"
    );
    flow::observe(f, id);
    let session = wire::open(f, a["token"].as_str().unwrap()).await;
    assert_eq!(
        discovery::list(f, a["token"].as_str().unwrap(), &session, 1).await["result"]["tools"][0]["name"],
        "read_record"
    );
    assert_eq!(
        calls::call(f, a, &session, 2, json!({})).await["result"]["structuredContent"]["account"],
        "None"
    );
    assert_eq!(&authority(f).await, expected);
    f.stop();
}

async fn authority(f: &Fixture) -> Value {
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new().filename(f.path().join("state.db")),
    )
    .await
    .unwrap();
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 14);
    let mut value = json!({});
    for (name, sql) in SNAPSHOTS {
        value[name] = sqlx::query_scalar::<_, String>(sql)
            .fetch_one(&pool)
            .await
            .unwrap()
            .into();
    }
    pool.close().await;
    value
}

const SNAPSHOTS: [(&str, &str); 3] = [
    (
        "bindings",
        "SELECT json_group_array(json_array(agent_id,registration,auth_spec)) FROM agent_credential_overrides",
    ),
    (
        "grants",
        "SELECT json_group_array(json_array(agent_id,instance,account_key,name,contract_digest)) FROM native_tool_grants",
    ),
    (
        "reviews",
        "SELECT json_group_array(json_array(instance,account_key,name,contract_digest)) FROM native_reviews",
    ),
];
