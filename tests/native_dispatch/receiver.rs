use super::{fixture::Fixture, process};
use std::{
    process::Stdio,
    time::{Duration, Instant},
};
pub struct Receiver {
    pub child: process::Guard,
    pub port: u16,
}
impl Receiver {
    pub fn start(f: &Fixture) -> Self {
        let mut command = process::command("python3");
        command.env("PYTHONDONTWRITEBYTECODE", "1");
        command
            .arg(format!(
                "{}/tests/native_dispatch/receiver.py",
                env!("CARGO_MANIFEST_DIR")
            ))
            .arg(f.path());
        let log = std::fs::File::create(f.path().join("receiver.log")).unwrap();
        command
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        let mut child = process::Guard(command.spawn().unwrap());
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(child.0.try_wait().unwrap().is_none());
            if let Ok(bytes) = std::fs::read(f.path().join("receiver-port.json"))
                && let Ok(port) = serde_json::from_slice(&bytes)
            {
                return Self { child, port };
            }
            assert!(Instant::now() < until, "receiver readiness deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn stop(mut self) {
        self.child.0.kill().unwrap();
        self.child.0.wait().unwrap();
    }
}
pub fn configure(f: &Fixture) {
    let file = f.path().join("config.yaml");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    config["mcp"] = serde_json::json!({"upstream_ca_bundle":f.path().join("ca.pem")});
    std::fs::write(file, config.to_string()).unwrap();
}
