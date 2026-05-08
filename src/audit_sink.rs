//! JSONL audit sink (T3.3 / R-F7 / PRD §14.1 #6).
//!
//! Operators tail this into Loki/Splunk/Vector. Each line mirrors the
//! `audit` SQLite columns 1:1, so a downstream pipeline written against
//! the SQL schema can also consume the JSONL stream verbatim.
//!
//! Rotation:
//! - Daily (UTC date in the filename suffix: `audit.jsonl.YYYY-MM-DD`)
//! - Cap-based (when current file exceeds `max_bytes`, rotate to a
//!   numbered overflow: `audit.jsonl.YYYY-MM-DD.<n>`).
//! - `keep_files` prunes the oldest rotated files so disk usage stays
//!   bounded.
//!
//! Best-effort: every IO failure is logged and swallowed — INF-26 says
//! audit must never block proxy traffic.

use crate::repo::audit::AuditEvent;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct JsonlSinkConfig {
    /// Base path. Rotated files share the same parent + stem, with
    /// suffixes for date and overflow index.
    pub path: PathBuf,
    /// Cap on a single rotated file's size in bytes. Default 100 MiB.
    pub max_bytes: u64,
    /// Number of rotated files to retain (oldest pruned beyond this).
    pub keep_files: usize,
}

impl Default for JsonlSinkConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/log/locksmith/audit.jsonl"),
            max_bytes: 100 * 1024 * 1024,
            keep_files: 14,
        }
    }
}

pub struct JsonlSink {
    cfg: JsonlSinkConfig,
    state: Mutex<SinkState>,
}

struct SinkState {
    /// Currently open file (None means we've fallen back to no-op).
    file: Option<std::fs::File>,
    /// Bytes written to the current file since open; used for cap-based
    /// rotation without an extra fstat per append.
    written: u64,
    /// UTC date string `YYYY-MM-DD` of the open file. Triggers daily
    /// rotation when the day rolls over.
    today: String,
}

impl JsonlSink {
    /// Construct the sink. Opens (or creates) the active file at
    /// construction time so misconfiguration surfaces at daemon startup
    /// rather than at first append. Returns an error if the parent
    /// directory cannot be created or the file cannot be opened.
    pub fn new(cfg: JsonlSinkConfig) -> std::io::Result<Self> {
        let parent = cfg.path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "jsonl path has no parent directory",
            )
        })?;
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
        let today = utc_date();
        let active = active_path(&cfg.path, &today);
        let file = OpenOptions::new().create(true).append(true).open(&active)?;
        let written = file.metadata()?.len();
        Ok(Self {
            cfg,
            state: Mutex::new(SinkState {
                file: Some(file),
                written,
                today,
            }),
        })
    }

    /// Append a single audit event as one JSONL line. Best-effort —
    /// any IO error is logged and the call still returns. The next
    /// successful tick of the writer will recover.
    pub async fn append(&self, event: &AuditEvent) {
        let line = serialize(event);
        let mut state = self.state.lock().await;
        // Daily rotation check.
        let today = utc_date();
        if today != state.today {
            self.rotate_to(&mut state, &today);
        }
        // Cap-based rotation: if writing this line would push us over
        // the cap, rotate first.
        let would_be = state.written.saturating_add(line.len() as u64);
        if would_be > self.cfg.max_bytes && state.written > 0 {
            // Same day, but cap exceeded: bump the overflow suffix.
            self.rotate_to(&mut state, &today);
        }
        if let Some(file) = state.file.as_mut() {
            if let Err(e) = file.write_all(line.as_bytes()) {
                warn!(error = %e, "audit jsonl append failed");
                state.file = None;
                return;
            }
            state.written = state.written.saturating_add(line.len() as u64);
        }
    }

    /// Force a flush of any buffered output. Useful for tests; the
    /// production daemon doesn't call this — fsync-on-every-write is
    /// the default since each append is short.
    pub async fn flush(&self) {
        let mut state = self.state.lock().await;
        if let Some(file) = state.file.as_mut()
            && let Err(e) = file.flush()
        {
            warn!(error = %e, "audit jsonl flush failed");
        }
    }

    /// Close the active file and open a fresh one with a new suffix,
    /// then prune older files beyond `keep_files`.
    fn rotate_to(&self, state: &mut SinkState, today: &str) {
        // Close current.
        state.file = None;
        state.written = 0;
        state.today = today.to_string();
        // Pick the next available filename for `today` — if a same-day
        // file already exists with content, append to it; otherwise
        // start at the base date suffix.
        let candidate = next_target(&self.cfg.path, today);
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&candidate)
        {
            Ok(file) => {
                let written = file.metadata().map(|m| m.len()).unwrap_or(0);
                state.file = Some(file);
                state.written = written;
            }
            Err(e) => {
                warn!(error = %e, path = %candidate.display(), "audit jsonl rotate-open failed");
            }
        }
        prune_oldest(&self.cfg.path, self.cfg.keep_files);
    }
}

fn serialize(e: &AuditEvent) -> String {
    let v = json!({
        "ts_ms": e.ts_ms,
        "event_class": e.event_class.as_str(),
        "event": e.event,
        "agent_public_id": e.agent_public_id,
        "operator_name": e.operator_name,
        "tool": e.tool,
        "upstream_host": e.upstream_host,
        "method": e.method,
        "path": e.path,
        "status": e.status,
        "latency_ms": e.latency_ms,
        "decision": e.decision.as_str(),
        "auth_method": e.auth_method,
        "origin_ip": e.origin_ip,
        "details": e.details,
    });
    let mut s = serde_json::to_string(&v).unwrap_or_default();
    s.push('\n');
    s
}

/// Filename for today's active file: `audit.jsonl.YYYY-MM-DD`.
fn active_path(base: &Path, today: &str) -> PathBuf {
    let parent = base.parent().unwrap_or_else(|| Path::new(""));
    let stem = base
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("audit.jsonl");
    parent.join(format!("{stem}.{today}"))
}

/// Compute the next filename for `today`. If a path with no suffix
/// exists and is below the cap caller has already moved past it; we
/// just pick the next overflow index — `audit.jsonl.YYYY-MM-DD.<n>`.
fn next_target(base: &Path, today: &str) -> PathBuf {
    let parent = base.parent().unwrap_or_else(|| Path::new(""));
    let stem = base
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("audit.jsonl");
    let primary = parent.join(format!("{stem}.{today}"));
    if !primary.exists() {
        return primary;
    }
    // Walk overflow indexes.
    for i in 1..=10_000 {
        let candidate = parent.join(format!("{stem}.{today}.{i}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    primary
}

/// Delete the oldest `audit.jsonl*` files in the parent directory until
/// at most `keep_files` remain. Pure best-effort.
fn prune_oldest(base: &Path, keep_files: usize) {
    if keep_files == 0 {
        return;
    }
    let parent = match base.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return,
    };
    let stem = match base.file_name().and_then(|s| s.to_str()) {
        Some(s) => s,
        None => return,
    };
    let entries = match std::fs::read_dir(parent) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(stem))
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            let mtime = meta.modified().ok()?;
            Some((mtime, e.path()))
        })
        .collect();
    if files.len() <= keep_files {
        return;
    }
    files.sort_by_key(|(t, _)| *t);
    let to_remove = files.len() - keep_files;
    for (_, p) in files.into_iter().take(to_remove) {
        if let Err(e) = std::fs::remove_file(&p) {
            warn!(error = %e, path = %p.display(), "audit jsonl prune failed");
        }
    }
}

fn utc_date() -> String {
    // YYYY-MM-DD in UTC. Computed by hand to avoid a chrono/time dep
    // — Locksmith doesn't otherwise need either crate.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = ymd_from_unix_secs(secs);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert unix epoch seconds to UTC (year, month, day). Standalone
/// implementation of the civil-from-days algorithm by Howard Hinnant
/// (public domain).
fn ymd_from_unix_secs(secs: i64) -> (i32, u32, u32) {
    let days = secs.div_euclid(86_400);
    // Days since 1970-01-01 → civil date via Hinnant's algorithm.
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = (y + i64::from(m <= 2)) as i32;
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ymd_known_dates() {
        assert_eq!(ymd_from_unix_secs(0), (1970, 1, 1));
        // 2000-01-01
        assert_eq!(ymd_from_unix_secs(946_684_800), (2000, 1, 1));
        // 2024-02-29 (leap year boundary)
        assert_eq!(ymd_from_unix_secs(1_709_164_800), (2024, 2, 29));
        // 2024-03-01 (day after leap day)
        assert_eq!(ymd_from_unix_secs(1_709_251_200), (2024, 3, 1));
        // 2025-12-31 23:59:59
        assert_eq!(ymd_from_unix_secs(1_767_225_599), (2025, 12, 31));
        // 2026-01-01 00:00:00
        assert_eq!(ymd_from_unix_secs(1_767_225_600), (2026, 1, 1));
    }
}
