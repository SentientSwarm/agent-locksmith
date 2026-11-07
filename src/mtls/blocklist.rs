//! T6.4 — Local emergency blocklist.
//!
//! File-backed list of revoked cert serials. Operators write the file
//! out-of-band via the `locksmith mtls revoke` CLI (T6.9) or directly;
//! `Blocklist` watches the file's mtime and reloads when it changes.
//!
//! Format: one hex serial per line; empty lines and lines starting with
//! `#` are ignored. Serials are canonicalised (see `canonical_serial`) so
//! `7A:11`, `0x7a11` and `007a11` all match the validator's `7a11`; a line
//! that is not hex is skipped with a warning.

use arc_swap::ArcSwap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
struct Snapshot {
    /// Lowercase hex serials.
    serials: HashSet<String>,
    /// File modification time and length at the last successful read.
    /// Sub-second mtime plus length catches a revoke written in the same
    /// second as the previous load.
    stamp: Option<(std::time::SystemTime, u64)>,
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
        let initial = match std::fs::metadata(&path) {
            Ok(meta) => Self::read(&path, Self::stamp(&meta))
                .inspect_err(|e| {
                    error!(path = %path.display(), error = %e, "mtls blocklist unreadable; starting empty")
                })
                .ok(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "mtls blocklist not readable; starting empty");
                None
            }
        }
        .unwrap_or_else(|| Snapshot {
            serials: HashSet::new(),
            stamp: None,
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
        let stamp = Self::stamp(&meta);
        if stamp == self.state.load().stamp {
            return false;
        }
        // The stamp is taken before the read: a write that lands during
        // the read changes the stamp again and forces another reload.
        match Self::read(&self.path, stamp) {
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
        canonical_serial(serial_hex).is_some_and(|s| self.state.load().serials.contains(&s))
    }

    pub fn len(&self) -> usize {
        self.state.load().serials.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn stamp(meta: &std::fs::Metadata) -> Option<(std::time::SystemTime, u64)> {
        meta.modified().ok().map(|m| (m, meta.len()))
    }

    fn read(path: &Path, stamp: Option<(std::time::SystemTime, u64)>) -> std::io::Result<Snapshot> {
        let raw = std::fs::read_to_string(path)?;
        let mut serials = HashSet::new();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match canonical_serial(trimmed) {
                Some(serial) => {
                    serials.insert(serial);
                }
                None => {
                    warn!(path = %path.display(), "mtls blocklist line is not a hex serial; skipped")
                }
            }
        }
        Ok(Snapshot { serials, stamp })
    }
}

/// The validator's form of a hex serial: lowercase, no `0x` prefix or
/// `:` separators, no leading zero bytes, an even number of digits
/// (`0` → `00`). `None` when the input is not hex.
pub fn canonical_serial(input: &str) -> Option<String> {
    let s = input.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let digits: String = s.chars().filter(|c| *c != ':').collect();
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let digits = digits.to_ascii_lowercase();
    let trimmed = digits.trim_start_matches('0');
    Some(match trimmed.len() {
        0 => "00".to_string(),
        n if n % 2 == 1 => format!("0{trimmed}"),
        _ => trimmed.to_string(),
    })
}

/// Replace `path` with `contents` by writing a synced sibling temp file
/// and renaming it over, so a reader never sees a truncated file. The new
/// file keeps the old one's mode.
pub fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    replace(path, contents, false)
}

/// `write_atomic` that also keeps the old file's owner and group on Unix,
/// so a `sudo locksmith mtls revoke` cannot make the blocklist unreadable
/// to the daemon. When the owner cannot be kept, the file is rewritten in
/// place (and synced), which keeps it.
pub fn write_atomic_keeping_owner(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    replace(path, contents, true)
}

fn replace(path: &Path, contents: &[u8], owner: bool) -> std::io::Result<()> {
    use std::io::Write;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("path has no file name"))?;
    let existing = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(std::io::Error::other(format!(
                "{} is a symlink; refusing to write through it",
                path.display()
            )));
        }
        Ok(meta) => Some(meta),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".tmp-{}-{nonce}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    // create_new (O_EXCL) never follows a planted symlink, and mode and
    // owner are set through the open descriptor, never by path.
    let staged = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        if let Some(meta) = &existing {
            file.set_permissions(meta.permissions())?;
            if owner {
                keep_owner(&file, meta)?;
            }
        }
        file.write_all(contents)?;
        file.sync_all()
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        if owner && existing.is_some() && e.kind() == std::io::ErrorKind::PermissionDenied {
            let mut file = open_no_follow(path)?;
            file.write_all(contents)?;
            return file.sync_all();
        }
        return Err(e);
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Open an existing file for an in-place rewrite without following a
/// symlink swapped in after the check.
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[cfg(unix)]
fn keep_owner(file: &std::fs::File, meta: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mine = file.metadata()?;
    if (mine.uid(), mine.gid()) == (meta.uid(), meta.gid()) {
        return Ok(());
    }
    std::os::unix::fs::fchown(file, Some(meta.uid()), Some(meta.gid()))
}

#[cfg(not(unix))]
fn keep_owner(_file: &std::fs::File, _meta: &std::fs::Metadata) -> std::io::Result<()> {
    Ok(())
}
