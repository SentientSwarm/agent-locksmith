use super::{AuditEvent, JsonlSink, serialize, utc_date};
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MirrorStatus {
    Absent,
    Written,
    Unavailable,
}

impl JsonlSink {
    /// Async mutex waiting is cancellable; synchronous file I/O is not.
    pub async fn append_status(&self, event: &AuditEvent) -> MirrorStatus {
        let line = serialize(event);
        let mut state = self.state.lock().await;
        let today = utc_date();
        if today != state.today
            || (state.written.saturating_add(line.len() as u64) > self.cfg.max_bytes
                && state.written > 0)
        {
            self.rotate_to(&mut state, &today);
        }
        let Some(file) = state.file.as_mut() else {
            return MirrorStatus::Unavailable;
        };
        if file.write_all(line.as_bytes()).is_err() {
            tracing::warn!("audit_jsonl_unavailable");
            state.file = None;
            return MirrorStatus::Unavailable;
        }
        state.written = state.written.saturating_add(line.len() as u64);
        MirrorStatus::Written
    }
}
