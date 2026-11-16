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

use std::ffi::OsString;

/// Variables a child may inherit, by exact name.
const CHILD_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "LANG",
    "TZ",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "all_proxy",
];

/// Variables a child may inherit, by prefix: 1Password's own settings and
/// session token (`op` needs them), XDG directories and locale.
const CHILD_ENV_PREFIXES: &[&str] = &["OP_", "XDG_", "LC_"];

/// Filter an environment down to what a child may see. The daemon's
/// environment holds the sealing keys and every env-backed upstream
/// credential, and a child is dumpable again after exec, so a same-uid
/// process could read whatever it inherits (AGENT-285).
pub fn child_env(env: impl IntoIterator<Item = (OsString, OsString)>) -> Vec<(OsString, OsString)> {
    env.into_iter()
        .filter(|(key, _)| {
            key.to_str().is_some_and(|k| {
                CHILD_ENV.contains(&k) || CHILD_ENV_PREFIXES.iter().any(|p| k.starts_with(p))
            })
        })
        .collect()
}

/// Give a child only [`child_env`] of the daemon's environment. Every
/// command the daemon spawns goes through this.
pub fn isolated_child(cmd: &mut std::process::Command) -> &mut std::process::Command {
    cmd.env_clear().envs(child_env(std::env::vars_os()))
}
