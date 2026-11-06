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
