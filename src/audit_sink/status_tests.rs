use super::{JsonlSink, JsonlSinkConfig, MirrorStatus};
use crate::repo::audit::AuditEvent;

#[tokio::test]
async fn write_failure_and_missing_file_never_report_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sink");
    let sink = JsonlSink::new(JsonlSinkConfig {
        path: path.clone(),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        sink.append_status(&AuditEvent::default()).await,
        MirrorStatus::Written
    );
    let readonly = dir.path().join("readonly");
    std::fs::write(&readonly, b"").unwrap();
    sink.state.lock().await.file = Some(std::fs::File::open(&readonly).unwrap());
    assert_eq!(
        sink.append_status(&AuditEvent::default()).await,
        MirrorStatus::Unavailable
    );
    assert_eq!(
        sink.append_status(&AuditEvent::default()).await,
        MirrorStatus::Unavailable
    );
}

#[tokio::test]
async fn absent_sink_is_distinct_and_mutex_wait_is_cancellable() {
    let dir = tempfile::tempdir().unwrap();
    let sink = JsonlSink::new(JsonlSinkConfig {
        path: dir.path().join("sink"),
        ..Default::default()
    })
    .unwrap();
    let pool = crate::migrations::open_and_migrate(&dir.path().join("state.db"))
        .await
        .unwrap();
    let repo = crate::repo::AuditRepository::new(pool);
    assert_eq!(
        repo.mirror_status(&AuditEvent::default()).await,
        MirrorStatus::Absent
    );
    let held = sink.state.lock().await;
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            sink.append_status(&AuditEvent::default())
        )
        .await
        .is_err()
    );
    drop(held);
    assert_eq!(
        sink.append_status(&AuditEvent::default()).await,
        MirrorStatus::Written
    );
}
