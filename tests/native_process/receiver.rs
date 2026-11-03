use super::process;
use std::time::{Duration, Instant};

pub struct Receiver {
    pub process: process::Guard,
    dir: tempfile::TempDir,
    pub port: u16,
}
impl Receiver {
    pub fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut c = process::command("python3");
        c.arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/native_process/receiver.py"
        ))
        .arg(dir.path());
        let mut process = process::Guard(c.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(process.0.try_wait().unwrap().is_none());
            if let Ok(value) = std::fs::read(dir.path().join("port.json"))
                && let Ok(port) = serde_json::from_slice::<u16>(&value)
            {
                return Self { process, dir, port };
            }
            assert!(Instant::now() < deadline, "receiver startup");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn count(&self) -> usize {
        serde_json::from_slice(&std::fs::read(self.dir.path().join("count.json")).unwrap()).unwrap()
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.process.0.kill();
        let _ = self.process.0.wait();
    }
}
