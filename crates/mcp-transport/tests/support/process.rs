use super::Error;
use locksmith_mcp_transport::{Client, Limits};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use tempfile::TempDir;

pub struct Receiver {
    pub url: String,
    pub certificate: String,
    dir: TempDir,
    child: Child,
}
impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Receiver {
    pub async fn start() -> Result<Self, Error> {
        Self::start_mode("405").await
    }
    pub async fn start_mode(mode: &str) -> Result<Self, Error> {
        let dir = tempfile::tempdir()?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let certificate = cert.cert.pem();
        std::fs::write(dir.path().join("cert.pem"), &certificate)?;
        std::fs::write(dir.path().join("key.pem"), cert.key_pair.serialize_pem())?;
        let child = Command::new("python3")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/receiver.py"))
            .arg(dir.path())
            .arg(mode)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut receiver = Self {
            url: String::new(),
            certificate,
            dir,
            child,
        };
        receiver.url = receiver.wait().await?;
        Ok(receiver)
    }
    async fn wait(&mut self) -> Result<String, Error> {
        for _ in 0..300 {
            if let Ok(port) = std::fs::read_to_string(self.dir.path().join("port"))
                && let Ok(port) = port.parse::<u16>()
                && port != 0
            {
                return Ok(format!("https://localhost:{port}/mcp"));
            }
            if self.child.try_wait()?.is_some() {
                return Err("receiver startup failed".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err("receiver startup timeout".into())
    }
    pub fn client(&self) -> Result<Client, Error> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        Ok(Client::new(
            Limits {
                response_bytes: 32768,
                ..Default::default()
            },
            vec![reqwest::Certificate::from_pem(self.certificate.as_bytes())?],
        )?)
    }
    pub fn counts(&self) -> Result<serde_json::Value, Error> {
        Ok(serde_json::from_slice(&std::fs::read(
            self.dir.path().join("counts.json"),
        )?)?)
    }
}
