//! T6.4 — Local emergency blocklist.
//!
//! File-backed list of revoked cert serials. Operators write the file
//! out-of-band via the `locksmith mtls revoke` CLI (T6.9) or directly;
//! `Blocklist` watches the file's mtime and reloads when it changes.
//!
//! Format: one hex serial per line; empty lines and lines starting with
//! `#` are ignored. Hex is case-insensitive; we lowercase before
//! comparing.

use arc_swap::ArcSwap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Debug, Clone)]
struct Snapshot {
    /// Lowercase hex serials.
    serials: HashSet<String>,
    /// File mtime as unix-secs at last successful read.
    mtime_secs: i64,
}

#[derive(Debug)]
pub struct Blocklist {
    path: PathBuf,
    state: ArcSwap<Snapshot>,
}

impl Blocklist {
    /// Open from a path. A missing file is OK — the blocklist starts
    /// empty and `reload_if_changed` will pick it up if/when it
    /// appears.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();
        let initial = Self::read(&path).unwrap_or_else(|_| Snapshot {
            serials: HashSet::new(),
            mtime_secs: 0,
        });
        Self {
            path,
            state: ArcSwap::from_pointee(initial),
        }
    }

    /// Re-read the file if its mtime changed since the last load.
    /// Returns true on a successful reload.
    pub fn reload_if_changed(&self) -> bool {
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return false;
        };
        let mtime_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if mtime_secs == self.state.load().mtime_secs {
            return false;
        }
        match Self::read(&self.path) {
            Ok(snap) => {
                info!(
                    path = %self.path.display(),
                    serials = snap.serials.len(),
                    "mtls blocklist reloaded"
                );
                self.state.store(Arc::new(snap));
                true
            }
            Err(e) => {
                warn!(path = %self.path.display(), error = %e, "mtls blocklist reload failed");
                false
            }
        }
    }

    pub fn contains(&self, serial_hex: &str) -> bool {
        self.state
            .load()
            .serials
            .contains(&serial_hex.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.state.load().serials.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read(path: &Path) -> std::io::Result<Snapshot> {
        let raw = std::fs::read_to_string(path)?;
        let mtime_secs = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut serials = HashSet::new();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            serials.insert(trimmed.to_ascii_lowercase());
        }
        Ok(Snapshot {
            serials,
            mtime_secs,
        })
    }
}
