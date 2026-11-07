use super::support as s;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn insert_refusal_and_submitted_commit_failure_have_distinct_safe_phases() {
    let (mut f, receiver, a) = s::setup().await;
    let id = a["public_id"].as_str().unwrap();
    let r = s::review(&f, id, json!({"workspace":"fixed"}), "read_record");
    s::grant(&f, id, &r);
    let session = s::open(&f, &a).await;
    let pool = s::pool(&f).await;
    sqlx::raw_sql("CREATE TRIGGER fail_admission BEFORE INSERT ON audit WHEN NEW.event='mcp_admitted' BEGIN SELECT RAISE(ABORT,'private-db-canary'); END;").execute(&pool).await.unwrap();
    let r = s::call(&f, &a, &session, 2, json!({"key":"read"})).await;
    assert_eq!(r["error"]["data"]["code"], "admission_audit_failed");
    let denied = s::audit(&f, "native_tool_denied").await;
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["phase"], "not_admitted");
    assert_eq!(denied[0]["outcome"], "not_submitted");
    sqlx::raw_sql("DROP TRIGGER fail_admission; CREATE TABLE parent_guard(id INTEGER PRIMARY KEY); CREATE TABLE deferred_guard(id INTEGER REFERENCES parent_guard(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER INSERT ON audit WHEN NEW.event='mcp_admitted' BEGIN INSERT INTO deferred_guard VALUES(1); END;").execute(&pool).await.unwrap();
    let r = s::call(&f, &a, &session, 3, json!({"key":"read"})).await;
    assert_eq!(r["error"]["data"]["code"], "admission_commit_failed");
    let unknown = s::audit(&f, "native_tool_unknown").await;
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0]["phase"], "commit_submitted");
    assert_eq!(unknown[0]["outcome"], "unknown");
    assert!(s::audit(&f, "mcp_admitted").await.is_empty());
    assert!(s::effects(&f).is_empty());
    let log = std::fs::read_to_string(f.path().join("daemon.log")).unwrap();
    assert!(!log.contains("private-db-canary"));
    pool.close().await;
    f.stop();
    receiver.stop();
}
