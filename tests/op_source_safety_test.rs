#[path = "account_bindings/logs.rs"]
mod logs;
use agent_locksmith::{
    migrations::open_and_migrate,
    operational_log_sink::OperationalLogEmitter,
    repo::{LogFilter, OperationalLogStore},
    secret::{OpCommand, OpResolver},
};
use secrecy::SecretString;

struct Failed;
impl OpCommand for Failed {
    fn read(&self, _: &str) -> Result<SecretString, String> {
        Err("private-op-error-sentinel".into())
    }
}

#[tokio::test]
async fn selected_op_error_is_classified_without_echoing_dependency_output() {
    let dir = tempfile::TempDir::new().unwrap();
    let pool = open_and_migrate(&dir.path().join("logs.db")).await.unwrap();
    let store = OperationalLogStore::new(pool);
    let emitter = std::sync::Arc::new(OperationalLogEmitter::spawn(store.clone(), 10));
    let capture = logs::Capture::default();
    let _guard = capture.start();
    let resolver = OpResolver::new(Box::new(Failed), Some(emitter));
    resolver.refresh(&["op://vault/selected/field".into()]);
    assert!(resolver.get("op://vault/selected/field").is_none());
    let rows = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let rows = store.query(&LogFilter::default()).await.unwrap();
            if !rows.is_empty() {
                break rows;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!capture.text().contains("private-op-error-sentinel"));
    assert!(!format!("{rows:?}").contains("private-op-error-sentinel"));
    assert!(format!("{rows:?}").contains("op_read_failed"));
}
