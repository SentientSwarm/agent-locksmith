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

/// Environment variables only the daemon itself may hold.
pub const DAEMON_SECRET_ENV: &[&str] = &[
    crate::oauth::sealing::SEALING_KEY_ENV,
    crate::secret::credential_sealing::CREDENTIAL_SEALING_KEY_ENV,
];

/// Strip [`DAEMON_SECRET_ENV`] from a child's environment. A child is
/// dumpable again after exec, so a same-uid process could otherwise read
/// the keys from it. Every command the daemon spawns goes through this.
pub fn without_daemon_secrets(cmd: &mut std::process::Command) -> &mut std::process::Command {
    for key in DAEMON_SECRET_ENV {
        cmd.env_remove(key);
    }
    cmd
}
