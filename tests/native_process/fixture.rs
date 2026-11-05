#[path = "assigned_port.rs"]
mod assigned_port;
use super::{pki::Pki, process};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub pki: Pki,
    pub port: u16,
    pub operator: String,
    pub daemon: Option<process::Guard>,
    pub http: reqwest::Client,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.daemon.take());
    }
}
impl Fixture {
    pub fn new() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::write(dir.path());
        let operator = operator(dir.path());
        // Port 0 in config; each start reads the OS-assigned port from the
        // daemon log, so no probed port can be taken first (AGENT-219).
        let port = 0;
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .add_root_certificate(reqwest::Certificate::from_pem(pki.ca.as_bytes()).unwrap())
            .build()
            .unwrap();
        let f = Self {
            dir,
            pki,
            port,
            operator,
            daemon: None,
            http,
        };
        f.config();
        f
    }
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }
    fn config(&self) {
        let p = |name| self.path().join(name);
        let value = json!({"listen":{"host":"127.0.0.1","port":self.port,"auth_mode":"both",
            "admin_socket":{"path":p("admin.sock")},"mtls":{"ca_bundle_path":p("ca.pem"),
            "server_cert_path":p("server.pem"),"server_key_path":p("server.key")}},
            "database":{"path":p("state.db")},"operator_credentials_path":p("operators.yaml"),
            "tools":[],"shutdown":{"drain_window_seconds":2}});
        std::fs::write(p("config.yaml"), value.to_string()).unwrap();
        std::fs::write(
            p("mcp.json"),
            json!({"protocol_version":"2025-11-25","allow_private_destination":true}).to_string(),
        )
        .unwrap();
    }
    pub async fn start(&mut self, binary: &str) {
        self.start_with_key(binary, None).await;
    }
    pub async fn start_with_key(&mut self, binary: &str, key: Option<&str>) {
        assert!(self.daemon.is_none());
        let _ = std::fs::remove_file(self.path().join("admin.sock"));
        let log = std::fs::File::create(self.path().join("daemon.log")).unwrap();
        // A restart binds a fresh OS-assigned port; `ready` reads it.
        self.port = 0;
        let mut c = process::command(binary);
        c.args(["--config"]).arg(self.path().join("config.yaml"));
        if let Some(key) = key {
            c.env("LOCKSMITH_CREDENTIAL_SEALING_KEY", key);
        }
        c.env("RUST_LOG", "agent_locksmith=info,rmcp=trace");
        c.stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        self.daemon = Some(process::Guard(c.spawn().unwrap()));
        self.ready().await;
    }
    async fn ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.assert_running();
            if self.port == 0
                && let Some(port) = assigned_port::read(self.path())
            {
                self.port = port;
            }
            if self.path().join("admin.sock").exists()
                && self
                    .http
                    .get(self.url("/livez"))
                    .send()
                    .await
                    .is_ok_and(|r| r.status() == 200)
            {
                break;
            }
            assert!(Instant::now() < deadline, "TLS daemon readiness deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    fn assert_running(&mut self) {
        assert!(
            self.daemon
                .as_mut()
                .unwrap()
                .0
                .try_wait()
                .unwrap()
                .is_none(),
            "daemon exited during setup"
        );
    }
    pub fn stop(&mut self) {
        let mut child = self.daemon.take().unwrap();
        let mut signal = process::command("kill");
        signal.args(["-TERM", &child.0.id().to_string()]);
        assert!(process::run(signal).status.success());
        assert!(
            process::wait(&mut child.0).success(),
            "graceful native daemon stop"
        );
        super::observations::joined(self.path());
    }
    pub fn command(&self, args: &[&str]) -> std::process::Command {
        let mut c = process::command(process::CLI);
        c.arg("--socket")
            .arg(self.path().join("admin.sock"))
            .args(["--format", "json"])
            .args(args);
        c.env("LOCKSMITH_OP_TOKEN", &self.operator);
        c
    }
    pub fn op(&self, args: &[&str]) -> Value {
        let r = process::run(self.command(args));
        assert!(
            r.status.success(),
            "operator command failed (output withheld)"
        );
        if r.stdout.is_empty() {
            Value::Null
        } else {
            process::json(r)
        }
    }
    pub fn enroll(&self, name: &str, endpoint: &str) -> Value {
        self.op(&[
            "tool",
            "put",
            "native",
            "--upstream",
            endpoint,
            "--auth",
            "none",
            "--egress",
            "direct",
            "--protocol",
            "mcp_streamable_http",
            "--mcp-config-file",
            self.path().join("mcp.json").to_str().unwrap(),
        ]);
        let a = self.op(&["agent", "register", "--name", name, "--allowlist", "native"]);
        self.op(&[
            "agent",
            "set-credential",
            a["public_id"].as_str().unwrap(),
            "native",
            "--no-auth",
        ]);
        a
    }
}
fn operator(path: &Path) -> String {
    let mut c = process::command(process::CLI);
    c.args(["bootstrap-operator", "--name", "fixture"]);
    let out = process::run(c);
    assert!(out.status.success());
    std::fs::write(path.join("operators.yaml"), out.stdout).unwrap();
    String::from_utf8(out.stderr)
        .unwrap()
        .lines()
        .map(str::trim)
        .find(|s| s.starts_with("lkop_"))
        .unwrap()
        .to_owned()
}
