use super::{fixture::Fixture, process};
use agent_locksmith::admin::uds_client::UdsClient;
use serde_json::{Value, json};
use std::{
    process::Stdio,
    time::{Duration, Instant},
};

const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
struct Twin {
    child: process::Guard,
    port: u16,
}
impl Twin {
    fn start(f: &Fixture) -> Self {
        Self::script(
            f,
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/oauth_consent/receiver.py"
            ),
        )
    }
    fn script(f: &Fixture, script: &str) -> Self {
        let mut command = process::command("python3");
        command.args(["-B", script]).arg(f.path());
        let log = std::fs::File::create(f.path().join("receiver.log")).unwrap();
        command
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        let mut child = process::Guard(command.spawn().unwrap());
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(child.0.try_wait().unwrap().is_none());
            if let Ok(bytes) = std::fs::read(f.path().join("provider-port.json")) {
                return Self {
                    child,
                    port: serde_json::from_slice(&bytes).unwrap(),
                };
            }
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }
    fn stop(mut self) {
        self.child.0.kill().unwrap();
        self.child.0.wait().unwrap();
    }
}
fn configure(f: &Fixture, t: &Twin) -> u16 {
    let callback = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = f.path().join("config.yaml");
    let mut c: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    c["oauth_consent"] = json!({"callback":{"address":format!("127.0.0.1:{callback}"),"cert_path":f.path().join("server.pem"),"key_path":f.path().join("server.key")},
        "profiles":[{"id":"fixture","kind":"controlled-linear-v1","client_id":"fixture-client","client_generation":1,
        "issuer":t.url(""),"authorization_endpoint":t.url("/authorize"),"token_endpoint":t.url("/token"),"resource":t.url("/mcp/readonly"),
        "redirect_profile_id":"loopback","redirect_uri":format!("https://127.0.0.1:{callback}/oauth/callback"),
        "expected_workspace":"00000000-0000-0000-0000-000000000041","expected_user":"00000000-0000-0000-0000-000000000042","ca_path":f.path().join("ca.pem")}]});
    std::fs::write(path, c.to_string()).unwrap();
    callback
}
async fn start(f: &mut Fixture) {
    start_binary(f, process::DAEMON).await;
}
async fn start_binary(f: &mut Fixture, binary: &str) {
    assert!(f.daemon.is_none());
    // Port 0 in config: each start binds a fresh port, read from the log.
    f.reset_assigned_port();
    let log = std::fs::File::create(f.path().join("daemon.log")).unwrap();
    let mut c = process::command(binary);
    c.arg("--config")
        .arg(f.path().join("config.yaml"))
        .env("LOCKSMITH_OAUTH_SEALING_KEY", KEY)
        .env("RUST_LOG", "agent_locksmith=info")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    f.daemon = Some(process::Guard(c.spawn().unwrap()));
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            f.daemon.as_mut().unwrap().0.try_wait().unwrap().is_none(),
            "daemon startup (private log retained until fixture drop)"
        );
        f.adopt_assigned_port();
        if f.path().join("admin.sock").exists()
            && f.http
                .get(f.url("/livez"))
                .send()
                .await
                .is_ok_and(|r| r.status() == 200)
        {
            break;
        }
        assert!(Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn request(f: &Fixture, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let (status, bytes) = UdsClient::new(f.path().join("admin.sock"))
        .request(
            method,
            path,
            &[
                ("authorization", &format!("Bearer {}", f.operator)),
                ("content-type", "application/json"),
            ],
            body.map(|b| b.to_string().into_bytes()),
        )
        .await
        .unwrap();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        },
    )
}
async fn registration(f: &Fixture, t: &Twin, callback: u16) -> Value {
    let auth = json!({"kind":"oauth_pkce","client_id":"fixture-client","redirect_uri":format!("https://127.0.0.1:{callback}/oauth/callback"),"scopes":["read"],"auth_url":t.url("/authorize"),"token_url":t.url("/token")});
    assert_eq!(request(f,"PUT","/admin/operator/tools/fixture",Some(json!({"upstream":t.url("/mcp/readonly"),"auth":auth,"egress":"direct","description":"controlled"}))).await.0,200);
    auth
}
fn connect(f: &Fixture, label: &str) -> Value {
    let status = f.op(&["oauth", "account-status", "fixture", "--label", label]);
    f.op(&[
        "oauth",
        "connect",
        "fixture",
        "--label",
        label,
        "--profile",
        "fixture",
        "--client-generation",
        "1",
        "--redirect-profile",
        "loopback",
        "--expected-config-revision",
        &status["config_revision"].to_string(),
    ])
}
fn callback(t: &Twin, port: u16, created: &Value) -> String {
    let url = reqwest::Url::parse(created["authorization_url"].as_str().unwrap()).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["scope"], "read");
    let mut callback =
        reqwest::Url::parse(&format!("https://127.0.0.1:{port}/oauth/callback")).unwrap();
    callback.query_pairs_mut().extend_pairs([
        ("state", query["state"].as_str()),
        ("iss", &t.url("")),
        ("code", "synthetic-code"),
    ]);
    callback.to_string()
}
fn counts(f: &Fixture) -> Value {
    serde_json::from_slice(&std::fs::read(f.path().join("counts.json")).unwrap()).unwrap()
}
async fn arrived(f: &Fixture, point: &str) {
    let until = Instant::now() + Duration::from_secs(5);
    while !f.path().join(format!("entered-{point}")).exists() {
        assert!(Instant::now() < until, "receiver hold arrival");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
pub async fn schemas() {
    let mut refused = 0;
    for variant in ["control", "required-null", "query-const", "query-enum"] {
        let mut f = Fixture::new();
        if variant != "control" {
            std::fs::write(f.path().join(format!("schema-{variant}")), "fixture").unwrap();
        }
        let t = Twin::start(&f);
        let port = configure(&f, &t);
        start(&mut f).await;
        registration(&f, &t, port).await;
        let created = connect(&f, "schema");
        let response = f
            .http
            .get(callback(&t, port, &created))
            .send()
            .await
            .unwrap();
        let arrivals = counts(&f);
        let account = f.op(&["oauth", "account-status", "fixture", "--label", "schema"]);
        println!(
            "schema={variant} status={} arrivals={arrivals} account={}",
            response.status(),
            account["state"]
        );
        if variant == "control" {
            assert_eq!(response.status(), 200);
            assert_eq!(account["state"], "connected_unbound");
            assert_eq!(arrivals["workspace"], 1);
            assert_eq!(arrivals["user"], 1);
        } else if response.status() == 400
            && account["state"] == "absent"
            && arrivals["workspace"] == 0
            && arrivals["user"] == 0
        {
            let poll = f.op(&[
                "oauth",
                "attempt-status",
                "fixture",
                created["attempt_id"].as_str().unwrap(),
            ]);
            assert_eq!(poll["safe_reason"], "schema_unsupported");
            refused += 1;
        }
        f.stop();
        t.stop();
    }
    assert_eq!(
        refused, 3,
        "all incompatible schemas refuse before identity calls/publication"
    );
}

pub async fn orphan() {
    let mut f = Fixture::new();
    let t = Twin::start(&f);
    let port = configure(&f, &t);
    start(&mut f).await;
    registration(&f, &t, port).await;
    let created = connect(&f, "orphan");
    assert_eq!(
        f.http
            .get(callback(&t, port, &created))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let original = f.op(&["oauth", "account-status", "fixture", "--label", "orphan"]);
    f.op(&["tool", "delete", "fixture"]);
    let (status, orphan) = request(
        &f,
        "GET",
        "/admin/operator/tools/fixture/oauth/accounts/orphan",
        None,
    )
    .await;
    println!(
        "orphan status={status} state={} receiver={}",
        orphan["state"],
        counts(&f)
    );
    assert_eq!(
        status, 200,
        "owned durable account remains inspectable without registration"
    );
    assert_eq!(orphan["state"], "reconnect_required");
    assert_eq!(orphan["config_revision"], Value::Null);
    assert_ne!(orphan["revision"], original["revision"]);
    let stale = |revision: &str| {
        f.command(&[
            "oauth",
            "disconnect",
            "fixture",
            "--label",
            "orphan",
            "--if-match",
            revision,
        ])
    };
    assert!(
        !process::run(stale(original["revision"].as_str().unwrap()))
            .status
            .success()
    );
    registration(&f, &t, port).await;
    assert!(
        !process::run(stale(orphan["revision"].as_str().unwrap()))
            .status
            .success()
    );
    let current = f.op(&["oauth", "account-status", "fixture", "--label", "orphan"]);
    assert_eq!(
        current["account_generation"],
        original["account_generation"]
    );
    f.op(&["tool", "delete", "fixture"]);
    let final_orphan = f.op(&["oauth", "account-status", "fixture", "--label", "orphan"]);
    let disconnected = f.op(&[
        "oauth",
        "disconnect",
        "fixture",
        "--label",
        "orphan",
        "--if-match",
        final_orphan["revision"].as_str().unwrap(),
    ]);
    assert_eq!(disconnected["state"], "disconnected");
    assert_eq!(
        disconnected["account_generation"],
        original["account_generation"]
    );
    assert_eq!(
        request(
            &f,
            "GET",
            "/admin/operator/tools/fixture/oauth/accounts/orphan",
            None
        )
        .await
        .0,
        404
    );
    assert_eq!(
        counts(&f),
        json!({"token":1,"workspace":1,"user":1,"other":0,"delete":1})
    );
    f.stop();
    t.stop();
}

pub async fn journey() {
    let mut f = Fixture::new();
    let t = Twin::start(&f);
    let port = configure(&f, &t);
    start(&mut f).await;
    let auth = registration(&f, &t, port).await;
    let agent = f.op(&[
        "agent",
        "register",
        "--name",
        "preselected",
        "--allowlist",
        "fixture",
    ]);
    let mut selected = auth;
    selected["session_label"] = json!("reader");
    assert_eq!(
        request(
            &f,
            "PUT",
            &format!(
                "/admin/operator/agents/{}/credentials/fixture",
                agent["public_id"].as_str().unwrap()
            ),
            Some(json!({"auth_spec":selected}))
        )
        .await
        .0,
        200
    );
    let created = connect(&f, "reader");
    let id = created["attempt_id"].as_str().unwrap();
    let poll = f.op(&["oauth", "attempt-status", "fixture", id]);
    assert!(poll.get("authorization_url").is_none());
    let response = f
        .http
        .get(callback(&t, port, &created))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let account = f.op(&["oauth", "account-status", "fixture", "--label", "reader"]);
    assert_eq!(account["state"], "connected_unbound");
    assert_eq!(account["granted_scope"], Value::Null);
    assert_eq!(
        counts(&f),
        json!({"token":1,"workspace":1,"user":1,"other":0,"delete":1})
    );
    f.op(&["oauth", "cancel", "fixture", id]);
    assert_eq!(
        f.op(&["oauth", "attempt-status", "fixture", id])["state"],
        "connected"
    );
    let response = f
        .http
        .get(f.url("/api/fixture/check"))
        .bearer_auth(agent["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let denied = process::run(f.command(&[
        "oauth",
        "bootstrap",
        "fixture",
        "--label",
        "reader",
        "--refresh-token",
        "synthetic-legacy",
    ]));
    assert!(!denied.status.success());
    assert_eq!(f.op(&["oauth", "list"]), json!([]));
    assert_eq!(counts(&f)["token"], 1);
    f.stop();
    start(&mut f).await;
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "reader"])["state"],
        "connected_unbound"
    );
    assert_eq!(counts(&f)["token"], 1);
    f.op(&[
        "oauth",
        "disconnect",
        "fixture",
        "--label",
        "reader",
        "--if-match",
        account["revision"].as_str().unwrap(),
    ]);
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "reader"])["state"],
        "absent"
    );
    std::fs::write(f.path().join("wrong-user"), "wrong").unwrap();
    let wrong = connect(&f, "wrong");
    assert_eq!(
        f.http
            .get(callback(&t, port, &wrong))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let refused = f.op(&[
        "oauth",
        "attempt-status",
        "fixture",
        wrong["attempt_id"].as_str().unwrap(),
    ]);
    assert_eq!(refused["safe_reason"], "user_mismatch");
    assert_eq!(refused["stage"], "user");
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "wrong"])["state"],
        "absent"
    );
    f.stop();
    t.stop();
    println!(
        "controlled CLI PASS: positive one token POST/two identity calls; wrong-user refusal; zero agent reuse; restart/disconnect; joined"
    );
}
pub async fn late() {
    for stop in [false, true] {
        let mut f = Fixture::new();
        let t = Twin::start(&f);
        let port = configure(&f, &t);
        start(&mut f).await;
        registration(&f, &t, port).await;
        std::fs::write(f.path().join("hold-token"), "hold").unwrap();
        let created = connect(&f, "held");
        let url = callback(&t, port, &created);
        let client = f.http.clone();
        let callback = tokio::spawn(async move { client.get(url).send().await });
        arrived(&f, "token").await;
        if stop {
            f.stop();
        } else {
            f.op(&[
                "oauth",
                "cancel",
                "fixture",
                created["attempt_id"].as_str().unwrap(),
            ]);
        }
        std::fs::write(f.path().join("release-token"), "release").unwrap();
        let _ = callback.await.unwrap();
        if stop {
            start(&mut f).await;
        }
        assert_eq!(
            f.op(&["oauth", "account-status", "fixture", "--label", "held"])["state"],
            "absent"
        );
        assert_eq!(counts(&f)["token"], 1);
        assert_eq!(counts(&f)["workspace"], 0);
        assert_eq!(counts(&f)["user"], 0);
        f.stop();
        t.stop();
    }
    println!(
        "held token response loses cancel/owned shutdown; no identity or account publication; joined"
    );
}

pub async fn principal() {
    let mut f = Fixture::new();
    let t = Twin::start(&f);
    let callback_port = configure(&f, &t);
    let operator_path = f.path().join("operators.yaml");
    let mut operators: Value =
        serde_yaml::from_slice(&std::fs::read(&operator_path).unwrap()).unwrap();
    operators["operators"][0]["cert_identity"] = json!("native-client");
    let mut command = process::command(process::CLI);
    command.args(["bootstrap-operator", "--name", "fixture"]);
    let second = process::run(command);
    assert!(second.status.success());
    let other = String::from_utf8(second.stderr)
        .unwrap()
        .lines()
        .map(str::trim)
        .find(|s| s.starts_with("lkop_"))
        .unwrap()
        .to_string();
    let other_record: Value = serde_yaml::from_slice(&second.stdout).unwrap();
    operators["operators"]
        .as_array_mut()
        .unwrap()
        .push(other_record["operators"][0].clone());
    std::fs::write(&operator_path, operators.to_string()).unwrap();
    let admin_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = f.path().join("config.yaml");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["listen"]["admin_https"] = json!({"enabled":true,"host":"127.0.0.1","port":admin_port,"cert_path":f.path().join("server.pem"),"key_path":f.path().join("server.key"),"auth_mode":"both","mtls":{"ca_bundle_path":f.path().join("ca.pem")}});
    std::fs::write(path, config.to_string()).unwrap();
    start(&mut f).await;
    registration(&f, &t, callback_port).await;
    let created = connect(&f, "owned");
    let id = created["attempt_id"].as_str().unwrap();
    let mut command = f.command(&["oauth", "attempt-status", "fixture", id]);
    command.env("LOCKSMITH_OP_TOKEN", other);
    let denied = process::run(command);
    assert_eq!(denied.status.code(), Some(4));
    let mtls = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .add_root_certificate(reqwest::Certificate::from_pem(f.pki.ca.as_bytes()).unwrap())
        .identity(reqwest::Identity::from_pem(f.pki.identity.as_bytes()).unwrap())
        .build()
        .unwrap();
    let url =
        format!("https://127.0.0.1:{admin_port}/admin/operator/tools/fixture/oauth/attempts/{id}");
    let current = mtls.get(&url).send().await.unwrap();
    assert_eq!(current.status(), 200);
    assert_eq!(current.json::<Value>().await.unwrap()["state"], "pending");
    let anonymous = f.http.get(&url).send().await.unwrap();
    assert_eq!(anonymous.status(), 401);
    assert_eq!(anonymous.headers()["cache-control"], "no-store");
    let agent = f.op(&[
        "agent",
        "register",
        "--name",
        "outsider",
        "--allowlist",
        "fixture",
    ]);
    let denied = f
        .http
        .get(&url)
        .bearer_auth(agent["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    assert!(
        !f.path().join("counts.json").exists(),
        "principal checks sent no provider request"
    );
    f.stop();
    t.stop();
    println!(
        "same-public-ID bearer/mTLS; duplicate-name principal and anonymous/agent denied; zero provider traffic"
    );
}

pub async fn embedded() {
    let mut f = Fixture::new();
    let t = Twin::start(&f);
    let port = configure(&f, &t);
    start(&mut f).await;
    registration(&f, &t, port).await;
    f.stop();
    let mut c = process::command(std::env::current_exe().unwrap().to_str().unwrap());
    c.args([
        "--exact",
        "embedded_consent_worker",
        "--ignored",
        "--nocapture",
    ])
    .env("CONSENT_EMBEDDED", f.path())
    .env("LOCKSMITH_OAUTH_SEALING_KEY", KEY);
    let log = std::fs::File::create(f.path().join("embedding.log")).unwrap();
    c.stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    let mut worker = process::Guard(c.spawn().unwrap());
    wait_path(&f.path().join("embedded-ready")).await;
    std::fs::write(f.path().join("hold-token"), "hold").unwrap();
    let created = connect(&f, "embedded");
    let url = callback(&t, port, &created);
    let client = f.http.clone();
    let request = tokio::spawn(async move { client.get(url).send().await });
    arrived(&f, "token").await;
    std::fs::write(f.path().join("shutdown"), "stop").unwrap();
    wait_path(&f.path().join("returned")).await;
    assert!(
        worker.0.try_wait().unwrap().is_none(),
        "embedding process remains alive"
    );
    start(&mut f).await; // Same canonical DB lock is available before old process exit.
    let before = f.op(&[
        "oauth",
        "attempt-status",
        "fixture",
        created["attempt_id"].as_str().unwrap(),
    ]);
    std::fs::write(f.path().join("release-token"), "release").unwrap();
    wait_path(&f.path().join("finished-token")).await;
    let _ = request.await.unwrap();
    assert_eq!(
        f.op(&[
            "oauth",
            "attempt-status",
            "fixture",
            created["attempt_id"].as_str().unwrap()
        ]),
        before
    );
    assert_eq!(
        f.op(&["oauth", "account-status", "fixture", "--label", "embedded"])["state"],
        "absent"
    );
    assert_eq!(counts(&f)["token"], 1);
    assert_eq!(counts(&f)["workspace"], 0);
    std::fs::write(f.path().join("finish"), "finish").unwrap();
    assert!(process::wait(&mut worker.0).success());
    f.stop();
    t.stop();
    println!(
        "embedded return/reacquire before process exit; late response cannot publish; all joined"
    );
}
async fn wait_path(path: &std::path::Path) {
    let reached = tokio::time::timeout(Duration::from_secs(12), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if reached.is_err() {
        // Name the phase and show the fixture's own logs: these waits only
        // time out on slower CI hosts, where the temporary directory is gone
        // by the time anyone looks.
        let dir = path.parent().unwrap();
        for log in ["embedding.log", "daemon.log", "receiver.log"] {
            let Ok(text) = std::fs::read_to_string(dir.join(log)) else {
                continue;
            };
            let text = text.replace(dir.to_str().unwrap(), "[fixture]");
            let lines: Vec<_> = text.lines().collect();
            for line in &lines[lines.len().saturating_sub(40)..] {
                eprintln!("{log}: {line}");
            }
        }
        panic!("owned phase not reached: {:?}", path.file_name().unwrap());
    }
}
pub async fn embedded_worker() {
    let Some(path) = std::env::var_os("CONSENT_EMBEDDED") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let mut config = agent_locksmith::config::parse_config_str(
        &std::fs::read_to_string(path.join("config.yaml")).unwrap(),
    )
    .unwrap();
    let mode = std::env::var("CONTROLLED_REFRESH_OWNER_MODE").unwrap_or_default();
    if mode == "startup" {
        // Every listener binds and is configured before any serves, so a
        // listener can fail only after serving starts: the admin HTTPS
        // certificate is a FIFO its task blocks on until the test writes an
        // invalid one, while a refresh is in flight.
        config.listen.admin_https=Some(serde_json::from_value(json!({"enabled":true,"host":"127.0.0.1","port":0,"cert_path":path.join("startup-cert"),"key_path":path.join("server.key"),"auth_mode":"mtls","mtls":{"ca_bundle_path":path.join("ca.pem")}})).unwrap());
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(path.join("ca.pem")).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    let coord = agent_locksmith::shutdown::ShutdownCoordinator::new(if mode == "normal" {
        Duration::from_secs(2)
    } else {
        Duration::from_millis(10)
    });
    // The config uses port 0: learn the bound port from the daemon.
    let (bound, addrs) = tokio::sync::oneshot::channel();
    let run = agent_locksmith::daemon::run_reporting(config, coord.clone(), Some(bound));
    let control_path = path.clone();
    let control_coord = coord.clone();
    let control = tokio::spawn(async move {
        let path = control_path;
        let coord = control_coord;
        let port = addrs.await.expect("bound addresses").agent.port();
        wait_path(&path.join("admin.sock")).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !client
                .get(format!("https://127.0.0.1:{port}/livez"))
                .send()
                .await
                .is_ok_and(|r| r.status() == 200)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        std::fs::write(path.join("embedded-ready"), "ready").unwrap();
        // In startup mode the failing listener stops the daemon itself.
        let requested = path.join("shutdown");
        tokio::select! {
            _ = wait_path(&requested) => coord.trigger(),
            _ = coord.shutdown_signal() => {}
        }
    });
    let (result, observed) = tokio::join!(run, control);
    observed.unwrap();
    if mode == "startup" {
        assert!(result.is_err());
    } else {
        result.unwrap();
    }
    std::fs::write(path.join("returned"), "returned").unwrap();
    wait_path(&path.join("finish")).await;
}

/// The callback listener binds last, before any listener task is spawned: a
/// held callback port fails startup without the agent listener ever serving.
pub async fn callback_bind_failure() {
    let f = Fixture::new();
    let t = Twin::start(&f);
    let port = configure(&f, &t);
    let _held = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let log = std::fs::File::create(f.path().join("daemon.log")).unwrap();
    let mut c = process::command(process::DAEMON);
    c.arg("--config")
        .arg(f.path().join("config.yaml"))
        .env("LOCKSMITH_OAUTH_SEALING_KEY", KEY)
        .env("RUST_LOG", "agent_locksmith=info,locksmithd=error")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    let mut daemon = process::Guard(c.spawn().unwrap());
    assert!(!process::wait(&mut daemon.0).success());
    let log = std::fs::read_to_string(f.path().join("daemon.log")).unwrap();
    assert!(
        log.contains("callback_bind_failed"),
        "startup error names the callback bind"
    );
    assert!(
        !log.contains("agent listener (mTLS) bound"),
        "no listener task was spawned"
    );
    t.stop();
    println!("held callback port fails startup before any listener serves");
}

#[path = "refresh_process.rs"]
pub mod refresh;

#[path = "../native_oauth/process.rs"]
pub mod native;

#[path = "hosted.rs"]
pub mod hosted;

#[path = "slack/mod.rs"]
pub mod slack;
