use std::{
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

pub const CLI: &str = env!("CARGO_BIN_EXE_locksmith");
pub const DAEMON: &str = env!("CARGO_BIN_EXE_locksmithd");

pub fn command(binary: &str) -> Command {
    let mut c = Command::new(binary);
    // Never inherit real providers, admin endpoints, sealing keys or proxy settings.
    c.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    c.env("LOCKSMITH_SEED_PATH", "");
    c
}

pub struct Guard(pub Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn wait(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "fixture child exceeded 20s deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn run(mut c: Command) -> Output {
    // Files avoid pipe-buffer deadlocks and remain private/automatically removed.
    let stdout = tempfile::NamedTempFile::new().unwrap();
    let stderr = tempfile::NamedTempFile::new().unwrap();
    c.stdout(Stdio::from(stdout.reopen().unwrap()));
    c.stderr(Stdio::from(stderr.reopen().unwrap()));
    let mut child = Guard(c.spawn().expect("fixture command spawns"));
    let status = wait(&mut child.0);
    Output {
        status,
        stdout: std::fs::read(stdout.path()).unwrap(),
        stderr: std::fs::read(stderr.path()).unwrap(),
    }
}

pub fn json(output: Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "CLI failed with {:?}; output withheld",
        output.status.code()
    );
    serde_json::from_slice(&output.stdout).expect("CLI JSON")
}
