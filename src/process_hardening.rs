//! AGENT-285 — keep same-uid processes out of the daemon.
//!
//! A classifier sidecar runs as Locksmith's own uid (the peer-uid check in
//! `inspection::sidecar` relies on it). Without this, that uid can read
//! `/proc/<pid>/environ`, which carries the sealing keys, and
//! `/proc/<pid>/mem`, and can ptrace-attach. Marking the process
//! non-dumpable makes the kernel refuse all three to anyone without
//! CAP_SYS_PTRACE, and also disables core dumps. Linux only; elsewhere this
//! is a no-op.

/// Call first in `locksmithd`'s `main`, before any secret is loaded.
pub fn deny_same_uid_inspection() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes plain integer arguments and touches
        // no memory we own.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
