//! A process-lifetime advisory lock, acquired before migrations or listeners.
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

pub(super) fn acquire(path: Option<&Path>) -> io::Result<Option<File>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let canonical = if path.exists() {
        path.canonicalize()?
    } else {
        parent.canonicalize()?.join(
            path.file_name()
                .ok_or_else(|| io::Error::other("invalid database path"))?,
        )
    };
    let mut name = canonical.into_os_string();
    name.push(".daemon.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(name)?;
    file.try_lock()
        .map_err(|_| io::Error::other("database already owned by another daemon"))?;
    Ok(Some(file))
}

/// Test-only: acquire once a brief hold ends. A process spawned anywhere
/// in the test binary shares the lock's open file until it execs, so a
/// lock just released can still read as held for a moment (AGENT-331).
/// A lock still held after `within` is refused.
#[cfg(test)]
pub(super) fn acquire_within(path: &Path, within: std::time::Duration) -> io::Result<Option<File>> {
    let started = std::time::Instant::now();
    loop {
        match acquire(Some(path)) {
            Err(_) if started.elapsed() < within => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    /// A process spawned elsewhere shares the lock's open file until it
    /// execs: modelled by a clone of the file, dropped a moment later.
    #[test]
    fn a_lock_held_only_by_a_shared_file_is_reacquired_once_that_ends() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.db");
        let lock = super::acquire(Some(&db)).unwrap().unwrap();
        let shared = lock.try_clone().unwrap();
        drop(lock);
        assert!(
            super::acquire(Some(&db)).is_err(),
            "still held by the clone"
        );
        let ends = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(shared);
        });
        assert!(super::acquire_within(&db, Duration::from_secs(5)).is_ok());
        ends.join().unwrap();
    }

    #[test]
    fn a_lock_still_held_past_the_wait_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.db");
        let _held = super::acquire(Some(&db)).unwrap();
        assert!(super::acquire_within(&db, Duration::from_millis(100)).is_err());
    }
}
