use super::{calls, discovery, fixture::Fixture, flow, process, receiver, wire};
use serde_json::{Value, json};

pub async fn setup() -> (Fixture, receiver::Receiver, Value, String, sqlx::SqlitePool) {
    let mut f = Fixture::new();
    receiver::configure(&f);
    let receiving = receiver::Receiver::start(&f);
    f.start(process::DAEMON).await;
    let a = f.enroll(
        "committed",
        &format!("https://localhost:{}/mcp", receiving.port),
    );
    discovery::grant(&f, a["public_id"].as_str().unwrap());
    let s = wire::open(&f, a["token"].as_str().unwrap()).await;
    discovery::list(&f, a["token"].as_str().unwrap(), &s, 1).await;
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(f.path().join("state.db"))
        .foreign_keys(true);
    let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
    (f, receiving, a, s, pool)
}
async fn count(pool: &sqlx::SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit WHERE event='mcp_admitted'")
        .fetch_one(pool)
        .await
        .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_insert_and_deferred_commit_failures_never_send_tool() {
    let (mut f, receiver, a, s, pool) = setup().await;
    sqlx::raw_sql("CREATE TRIGGER fail_admission BEFORE INSERT ON audit WHEN NEW.event='mcp_admitted' BEGIN SELECT RAISE(ABORT,'fixture'); END;").execute(&pool).await.unwrap();
    let r = calls::call(&f, &a, &s, 2, json!({})).await;
    assert_eq!(r["error"]["data"]["code"], "admission_audit_failed");
    assert_eq!(count(&pool).await, 0);
    assert!(calls::effects(&f).is_empty());
    sqlx::raw_sql("DROP TRIGGER fail_admission; CREATE TABLE parent_guard(id INTEGER PRIMARY KEY); CREATE TABLE deferred_guard(id INTEGER REFERENCES parent_guard(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER INSERT ON audit WHEN NEW.event='mcp_admitted' BEGIN INSERT INTO deferred_guard VALUES(1); END;").execute(&pool).await.unwrap();
    let r = calls::call(&f, &a, &s, 3, json!({})).await;
    assert_eq!(r["error"]["data"]["code"], "admission_commit_failed", "{r}");
    assert_eq!(count(&pool).await, 0);
    assert!(calls::effects(&f).is_empty());
    sqlx::query("DROP TRIGGER fail_commit")
        .execute(&pool)
        .await
        .unwrap();
    assert!(calls::call(&f, &a, &s, 4, json!({})).await["result"].is_object());
    assert_eq!(count(&pool).await, 1);
    assert_eq!(calls::effects(&f).len(), 1);
    pool.close().await;
    f.stop();
    receiver.stop();
}
pub async fn arrived(f: &Fixture, name: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !f.path().join(format!("arrived-{name}.json")).exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_preparation_cannot_switch_to_new_grant_revision() {
    let (mut f, receiver, a, s, pool) = setup().await;
    std::fs::write(
        f.path().join("behavior.json"),
        json!({"prepare_hold":"prepare"}).to_string(),
    )
    .unwrap();
    let response=wire::post(&f,a["token"].as_str().unwrap(),Some(&s),json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_record","arguments":{}}})).await;
    arrived(&f, "prepare").await;
    replace_same_grants(&f, &a);
    std::fs::write(f.path().join("release-prepare.json"), b"true").unwrap();
    assert!(response.text().await.unwrap().contains("authority_changed"));
    assert_eq!(count(&pool).await, 0);
    assert!(calls::effects(&f).is_empty());
    pool.close().await;
    f.stop();
    receiver.stop();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_disconnect_during_preparation_has_zero_tool_effect() {
    let (mut f, receiver, a, s, pool) = setup().await;
    std::fs::write(
        f.path().join("behavior.json"),
        json!({"prepare_hold":"disconnect"}).to_string(),
    )
    .unwrap();
    let response=wire::post(&f,a["token"].as_str().unwrap(),Some(&s),json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_record","arguments":{}}})).await;
    arrived(&f, "disconnect").await;
    drop(response);
    closed(&f, &a, &s).await;
    std::fs::write(f.path().join("release-disconnect.json"), b"true").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(count(&pool).await, 0);
    assert!(calls::effects(&f).is_empty());
    pool.close().await;
    f.stop();
    receiver.stop();
}
async fn closed(f: &Fixture, a: &Value, s: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        for id in 100..300 {
            let r = wire::post(
                f,
                a["token"].as_str().unwrap(),
                Some(s),
                json!({"jsonrpc":"2.0","id":id,"method":"ping"}),
            )
            .await;
            if r.status() == 404 {
                return;
            }
            assert_eq!(r.status(), 200);
            let _ = r.text().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("disconnected session remained usable");
    })
    .await
    .unwrap();
}

fn replace_same_grants(f: &Fixture, a: &Value) {
    let current = flow::show(f, a["public_id"].as_str().unwrap());
    let file = flow::write(
        f,
        json!({"source":current["source"],"generation":current["observation"]["generation"],"revision":current["grant_revision"],"tools":current["tools"]}),
    );
    f.op(&[
        "agent",
        "mcp-grants",
        "replace",
        "native",
        "--agent",
        a["public_id"].as_str().unwrap(),
        "--file",
        &file,
    ]);
}
