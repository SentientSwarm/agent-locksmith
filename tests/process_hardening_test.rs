//! AGENT-285: a process running as locksmithd's own uid (such as a
//! classifier sidecar) must not be able to read the daemon's environment,
//! which carries the sealing keys, or its memory.
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn same_uid_processes_cannot_read_the_daemon_environment() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root may read any process environment");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // Opening a FIFO blocks until a writer appears, so the daemon stays
    // alive at config load, after startup hardening has run.
    let fifo = dir.path().join("config.yaml");
    let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut child = Kill(
        Command::new(env!("CARGO_BIN_EXE_locksmithd"))
            .arg("--config")
            .arg(&fifo)
            .env("LOCKSMITH_HARDENING_PROBE", "visible-if-unhardened")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let environ = format!("/proc/{}/environ", child.0.id());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read(&environ) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // A zombie's files are refused too; the daemon must be live.
                assert!(child.0.try_wait().unwrap().is_none(), "locksmithd exited");
                break;
            }
            Ok(_) | Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            other => panic!(
                "daemon environment still readable by its own uid: {:?}",
                other.map(|b| b.len())
            ),
        }
    }
    let mem = format!("/proc/{}/mem", child.0.id());
    assert_eq!(
        std::fs::File::open(&mem).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
