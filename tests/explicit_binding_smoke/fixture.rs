use super::process::{self, Guard};
use std::{
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};

pub struct Fixture {
    pub dir: Option<tempfile::TempDir>,
    pub config: PathBuf,
    pub socket: PathBuf,
    pub db: PathBuf,
    pub operator: String,
    pub upstream: String,
    pub port: u16,
    pub daemon: Option<Guard>,
    pub starts: usize,
    /// Whether the running daemon is a retained prior binary rather than
    /// this build, so version checks can tell the two apart.
    pub prior: bool,
    pub http: reqwest::Client,
    pub tokens: std::cell::RefCell<Vec<String>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.daemon.take());
    }
}
impl Fixture {
    pub fn path(&self) -> &std::path::Path {
        self.dir.as_ref().unwrap().path()
    }
    pub fn new(upstream: &str) -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("config.yaml");
        let socket = dir.path().join("admin.sock");
        let db = dir.path().join("locksmith.db");
        // A stable probed port, unlike the other daemon tests (AGENT-219):
        // the upgrade probes restart the same config under prior binaries,
        // which log the configured address rather than the bound one. A
        // collision cannot be mistaken for readiness, because `ready` also
        // requires this fixture's own admin socket, which a daemon that
        // failed to bind the agent port never creates.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let operator = super::setup::operator(dir.path());
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let f = Self {
            dir: Some(dir),
            config,
            socket,
            db,
            operator,
            upstream: upstream.into(),
            port,
            daemon: None,
            starts: 0,
            prior: false,
            http,
            tokens: std::cell::RefCell::new(Vec::new()),
        };
        super::setup::config(&f);
        f
    }
    pub async fn start(&mut self) {
        self.start_with_env(&[]).await;
    }
    pub async fn start_with_env(&mut self, env: &[(&str, &str)]) {
        assert!(self.daemon.is_none());
        let _ = std::fs::remove_file(&self.socket);
        let log = self.path().join(format!("daemon-{}.log", self.starts));
        self.starts += 1;
        let mut c = super::docs::fixture(self, super::docs::SETUP, "start");
        c.env("SMOKE_X", super::upstream::X)
            .env("SMOKE_Y", super::upstream::Y)
            .env("SMOKE_EMPTY", "");
        c.envs(env.iter().copied());
        self.prior = env
            .iter()
            .any(|(k, v)| *k == "LOCKSMITHD_BIN" && *v != super::process::DAEMON);
        c.stdout(Stdio::from(std::fs::File::create(&log).unwrap()));
        c.stderr(Stdio::from(
            std::fs::OpenOptions::new().append(true).open(log).unwrap(),
        ));
        self.daemon = Some(Guard(c.spawn().unwrap()));
        self.ready().await;
    }
    async fn ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                self.daemon
                    .as_mut()
                    .unwrap()
                    .0
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "daemon exited before readiness; private log withheld"
            );
            let ready = self.http.get(self.url("/readyz")).send().await;
            if self.socket.exists() && ready.is_ok_and(|r| r.status() == 200) {
                break;
            }
            assert!(Instant::now() < deadline, "daemon readiness deadline");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(
            self.http
                .get(self.url("/livez"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    pub fn stop(&mut self) {
        let mut child = self.daemon.take().expect("running fixture");
        let status = process::run({
            let mut c = process::command("kill");
            c.args(["-TERM", &child.0.id().to_string()]);
            c
        });
        assert!(status.status.success(), "fixture SIGTERM");
        assert!(
            process::wait(&mut child.0).success(),
            "graceful fixture shutdown"
        );
    }
    pub fn cleanup(mut self) {
        self.stop();
        let address = format!("127.0.0.1:{}", self.port).parse().unwrap();
        assert!(std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err());
        let path = self.path().to_owned();
        self.dir
            .take()
            .unwrap()
            .close()
            .expect("fixture state removed");
        assert!(!path.exists());
    }
    pub fn cli(&self, args: &[&str]) -> std::process::Command {
        let mut c = process::command(process::CLI);
        c.arg("--socket")
            .arg(&self.socket)
            .args(["--format", "json"])
            .args(args);
        c.env("LOCKSMITH_OP_TOKEN", &self.operator);
        c
    }
    pub fn op(&self, args: &[&str]) -> serde_json::Value {
        let output = process::run(self.cli(args));
        assert!(
            output.status.success(),
            "operator CLI {:?} failed; output withheld",
            args.first()
        );
        let text = String::from_utf8_lossy(&output.stdout);
        super::safety::no_values(&text, &[]);
        if output.stdout.is_empty() {
            serde_json::Value::Null
        } else {
            process::json(output)
        }
    }
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}
