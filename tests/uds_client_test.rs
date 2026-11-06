//! UDS HTTP client (M2 wiring): the CLI talks to the daemon over a
//! Unix-domain socket. The client must speak HTTP/1.1 over the socket
//! and round-trip request bodies + auth headers.

use agent_locksmith::admin::uds_client::UdsClient;
use agent_locksmith::config::parse_config_str;
use agent_locksmith::{argon2_helper, daemon, token};
use serde_json::{Value, json};
use std::time::Duration;
use tempfile::TempDir;

#[tokio::test]
async fn uds_client_round_trips_register_and_status() {
    let dir = TempDir::new().unwrap();
    let socket_path = dir.path().join("admin.sock");
    let ops_path = dir.path().join("operators.yaml");

    // Operator credentials.
    let op_tok = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_token_wire = op_tok.wire_format();
    let op_hash = argon2_helper::hash(&secrecy::SecretString::from(
        op_tok.secret.expose().to_string(),
    ))
    .unwrap();
    std::fs::write(
        &ops_path,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_tok.public_id.as_str(),
            op_hash
        ),
    )
    .unwrap();

    // The test never talks to the agent listener, so it binds an
    // OS-assigned port. A probed-then-released port can be taken before
    // the daemon binds it, failing startup before the admin socket exists.
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: 0
  admin_socket:
    path: "{sock}"
operator_credentials_path: "{ops}"
database:
  path: "{db}"
tools: []
"#,
        sock = socket_path.display(),
        ops = ops_path.display(),
        db = dir.path().join("locksmith.db").display(),
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let (coord, mut handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;

    // Wait for socket to appear. A daemon that exits during startup is
    // reported with its own error instead of a bare missing-socket timeout.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !socket_path.exists() {
        if handle.is_finished() {
            panic!(
                "daemon exited before binding the socket: {:?}",
                (&mut handle).await
            );
        }
        if std::time::Instant::now() > deadline {
            coord.trigger();
            let exit = tokio::time::timeout(Duration::from_secs(6), &mut handle).await;
            panic!("socket never appeared; daemon after shutdown: {exit:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let client = UdsClient::new(&socket_path);

    // POST /admin/operator/agents — register an agent (UC-1).
    let body = json!({ "name": "agent-1" });
    let (status, bytes) = client
        .request(
            "POST",
            "/admin/operator/agents",
            &[
                ("authorization", format!("Bearer {op_token_wire}").as_str()),
                ("content-type", "application/json"),
            ],
            Some(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .expect("request ok");
    assert_eq!(status, 200, "operator can create agent over UDS");
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    let agent_token = parsed["token"].as_str().unwrap().to_string();
    assert!(agent_token.starts_with("lk_"));

    // GET /admin/agent/status with the new token (UC-3).
    let (status, bytes) = client
        .request(
            "GET",
            "/admin/agent/status",
            &[("authorization", format!("Bearer {agent_token}").as_str())],
            None,
        )
        .await
        .expect("status request ok");
    assert_eq!(status, 200, "agent can self-status over UDS");
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["name"], "agent-1");

    coord.trigger();
    let _ = tokio::time::timeout(Duration::from_secs(6), handle).await;
}

#[tokio::test]
async fn uds_client_returns_error_for_missing_socket() {
    let client = UdsClient::new("/tmp/agent-locksmith-nonexistent.sock");
    let err = client
        .request("GET", "/admin/agent/status", &[], None)
        .await
        .expect_err("connect must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("connect") || msg.contains("No such file") || msg.contains("not found"),
        "error mentions connect failure; got: {msg}"
    );
}
