use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pre-compact binaries via LOCKSMITH_COMPACT_PRIOR_CLI/DAEMON"]
async fn actual_prior_opt_in_parser_cost_and_current_repair() {
    let prior_cli = std::env::var("LOCKSMITH_COMPACT_PRIOR_CLI").unwrap();
    let prior_daemon = std::env::var("LOCKSMITH_COMPACT_PRIOR_DAEMON").unwrap();
    let mut f = fixture::Fixture::new();
    receiver::configure(&f);
    let up = receiver::Receiver::start(&f);
    f.start(&prior_daemon).await;
    let a = f.enroll(
        "prior-compact",
        &format!("https://localhost:{}/mcp", up.port),
    );
    let token = a["token"].as_str().unwrap();
    assert_eq!(post(&f, token, None, wire::init()).await.status(), 404);
    f.stop();
    f.start(process::DAEMON).await;
    // Existing metadata remains readable by the actual old CLI on the new daemon.
    let mut cmd = process::command(&prior_cli);
    cmd.arg("--socket")
        .arg(f.path().join("admin.sock"))
        .args(["--format", "json", "tool", "get", "native"])
        .env("LOCKSMITH_OP_TOKEN", &f.operator);
    let old_read = process::run(cmd);
    assert!(old_read.status.success());
    std::fs::write(
        f.path().join("mcp.json"),
        json!({"protocol_version":"2025-11-25","allow_private_destination":true,"compact":true})
            .to_string(),
    )
    .unwrap();
    f.op(&[
        "tool",
        "put",
        "native",
        "--upstream",
        &format!("https://localhost:{}/mcp", up.port),
        "--auth",
        "none",
        "--egress",
        "direct",
        "--protocol",
        "mcp_streamable_http",
        "--mcp-config-file",
        f.path().join("mcp.json").to_str().unwrap(),
    ]);
    let mut cmd = process::command(&prior_cli);
    cmd.arg("--socket")
        .arg(f.path().join("admin.sock"))
        .args(["--format", "json", "tool", "get", "native"])
        .env("LOCKSMITH_OP_TOKEN", &f.operator);
    let old_read = process::run(cmd);
    assert!(old_read.status.success());
    let value: Value = serde_json::from_slice(&old_read.stdout).unwrap();
    assert_eq!(value["mcp"]["compact"], true);
    f.stop();
    let log = std::fs::File::create(f.path().join("prior.log")).unwrap();
    let mut cmd = process::command(&prior_daemon);
    cmd.arg("--config")
        .arg(f.path().join("config.yaml"))
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    let mut prior = process::Guard(cmd.spawn().unwrap());
    let until = std::time::Instant::now() + std::time::Duration::from_secs(8);
    let status = loop {
        if let Some(s) = prior.0.try_wait().unwrap() {
            break s;
        }
        assert!(
            std::time::Instant::now() < until,
            "expected typed prior startup refusal"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(!status.success());
    let log = std::fs::read_to_string(f.path().join("prior.log")).unwrap();
    assert!(!log.is_empty(), "prior startup error must be observable");
    println!(
        "prior startup exit failure observed after opt-in; field_named_in_diagnostic={}",
        log.contains("compact")
    );
    assert!(f.http.get(f.url("/livez")).send().await.is_err());
    println!(
        "prior_pre_compact: CLI reads new JSON; daemon refuses stored compact=true before HTTP availability"
    );
    f.start(process::DAEMON).await;
    // Reupgrade is available; toggle invalidated the old connection authority.
    assert_eq!(post(&f, token, None, wire::init()).await.status(), 403);
    f.op(&[
        "agent",
        "modify",
        a["public_id"].as_str().unwrap(),
        "--allowlist",
        "native",
    ]);
    f.op(&[
        "agent",
        "set-credential",
        a["public_id"].as_str().unwrap(),
        "native",
        "--no-auth",
    ]);
    grant(&f, a["public_id"].as_str().unwrap());
    let response = post(&f, token, None, wire::init()).await;
    assert_eq!(response.status(), 200);
    response.text().await.unwrap();
    f.stop();
    up.stop();
}
