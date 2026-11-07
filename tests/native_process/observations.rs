use serde_json::Value;
use std::path::Path;

pub fn joined(path: &Path) {
    let log = std::fs::read_to_string(path.join("daemon.log")).unwrap();
    let event = log
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|row| row["fields"]["message"] == "native sessions joined")
        .expect("daemon emitted actual joined-resource observation");
    let fields = &event["fields"];
    assert_eq!(fields["entries"], 0);
    assert_eq!(fields["workers_created"], fields["workers_joined"]);
    assert_eq!(fields["services_created"], fields["services_joined"]);
    assert!(!log.contains("secret-canary-202"));
    assert!(!log.contains("private-id-202"));
}

pub async fn audit(path: &Path) {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path.join("state.db"))
        .read_only(true);
    let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT event,details FROM audit WHERE event LIKE 'native_%'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(rows.iter().any(|(event, _)| event == "native_tool_denied"));
    for (_, details) in rows {
        let details = details.unwrap();
        assert!(!details.contains("secret-canary-202"));
        assert!(!details.contains("private-id-202"));
    }
    pool.close().await;
}
