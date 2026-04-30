//! T3.3 — JSONL audit sink. Mirrors the SQLite columns 1:1. Daily +
//! size-based rotation. Best-effort: filesystem failures don't
//! propagate.

use agent_locksmith::audit_sink::{JsonlSink, JsonlSinkConfig};
use agent_locksmith::repo::audit::{AuditEvent, Decision, EventClass};
use std::path::Path;
use tempfile::TempDir;

fn event(event: &str) -> AuditEvent {
    AuditEvent {
        ts_ms: 1_700_000_000_000,
        event_class: EventClass::Operator,
        event: event.into(),
        operator_name: Some("alice".into()),
        agent_public_id: Some("ag_xyz".into()),
        decision: Decision::Allowed,
        ..AuditEvent::default()
    }
}

fn read_active_file(dir: &Path) -> Option<String> {
    let entries: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("audit.jsonl"))
        .collect();
    if entries.is_empty() {
        return None;
    }
    let mut bodies: Vec<(String, String)> = entries
        .into_iter()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let body = std::fs::read_to_string(e.path()).ok()?;
            Some((name, body))
        })
        .collect();
    bodies.sort_by(|a, b| a.0.cmp(&b.0));
    Some(
        bodies
            .into_iter()
            .map(|(_, b)| b)
            .collect::<Vec<_>>()
            .join(""),
    )
}

#[tokio::test]
async fn writes_single_line_per_event() {
    let dir = TempDir::new().unwrap();
    let cfg = JsonlSinkConfig {
        path: dir.path().join("audit.jsonl"),
        max_bytes: 100 * 1024 * 1024,
        keep_files: 14,
    };
    let sink = JsonlSink::new(cfg).unwrap();
    sink.append(&event("agent_create")).await;
    sink.append(&event("agent_revoke")).await;
    sink.flush().await;
    drop(sink);
    let body = read_active_file(dir.path()).expect("file present");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "one line per event");
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON");
    assert_eq!(parsed["event"], "agent_create");
    assert_eq!(parsed["event_class"], "operator");
    assert_eq!(parsed["operator_name"], "alice");
    assert_eq!(parsed["decision"], "allowed");
}

#[tokio::test]
async fn cap_based_rotation_triggers_on_overflow() {
    let dir = TempDir::new().unwrap();
    let cfg = JsonlSinkConfig {
        path: dir.path().join("audit.jsonl"),
        max_bytes: 200, // tiny so a few events trip rotation
        keep_files: 5,
    };
    let sink = JsonlSink::new(cfg).unwrap();
    for _ in 0..30 {
        sink.append(&event("filler")).await;
    }
    sink.flush().await;
    drop(sink);
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("audit.jsonl"))
        .collect();
    assert!(
        entries.len() >= 2,
        "rotation produced multiple files; got: {} ({:?})",
        entries.len(),
        entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn keep_files_prunes_oldest_rotations() {
    let dir = TempDir::new().unwrap();
    let cfg = JsonlSinkConfig {
        path: dir.path().join("audit.jsonl"),
        max_bytes: 80,
        keep_files: 2,
    };
    let sink = JsonlSink::new(cfg).unwrap();
    for _ in 0..200 {
        sink.append(&event("e")).await;
    }
    sink.flush().await;
    drop(sink);
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("audit.jsonl"))
        .collect();
    assert!(
        entries.len() <= 2,
        "keep_files=2 prunes older rotations; saw {} files",
        entries.len()
    );
}

#[tokio::test]
async fn daemon_mirrors_audit_inserts_to_jsonl() {
    use agent_locksmith::config::parse_config_str;
    use agent_locksmith::{argon2_helper, daemon, token};
    use std::time::Duration;

    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("admin.sock");
    let ops = dir.path().join("operators.yaml");
    let db = dir.path().join("locksmith.db");
    let jsonl = dir.path().join("audit.jsonl");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let op_tok = token::StructuredToken::generate(token::TokenNamespace::Operator);
    let op_token_wire = op_tok.wire_format();
    std::fs::write(
        &ops,
        format!(
            "operators:\n  - name: alice\n    public_id: \"{}\"\n    token_hash: \"{}\"\n",
            op_tok.public_id.as_str(),
            argon2_helper::hash(&secrecy::SecretString::from(
                op_tok.secret.expose().to_string()
            ))
            .unwrap()
        ),
    )
    .unwrap();
    let yaml = format!(
        r#"
listen:
  host: "127.0.0.1"
  port: {port}
  admin_socket:
    path: "{sock}"
operator_credentials_path: "{ops}"
database:
  path: "{db}"
audit:
  retention_days: 90
  sweep_interval_seconds: 3600
  jsonl_path: "{jsonl}"
tools: []
"#,
        sock = socket.display(),
        ops = ops.display(),
        db = db.display(),
        jsonl = jsonl.display(),
    );
    let cfg = parse_config_str(&yaml).unwrap();
    let (coord, handle) = daemon::run_with_drain_window(cfg, Duration::from_secs(5)).await;

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !socket.exists() {
        if std::time::Instant::now() > deadline {
            panic!("socket never bound");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Drive an admin call that emits one operator audit row.
    let client = agent_locksmith::admin::uds_client::UdsClient::new(&socket);
    let body = serde_json::json!({ "name": "audited-by-jsonl" });
    let (status, _) = client
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
        .expect("create agent ok");
    assert_eq!(status, 200);

    // Wait for the JSONL line to appear.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let body = loop {
        if let Some(b) = read_active_file(dir.path())
            && b.contains("agent_create")
        {
            break b;
        }
        if std::time::Instant::now() > deadline {
            panic!("JSONL line never appeared");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let line = body
        .lines()
        .find(|l| l.contains("agent_create"))
        .expect("line found");
    let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
    assert_eq!(parsed["event"], "agent_create");
    assert_eq!(parsed["operator_name"], "alice");

    coord.trigger();
    let _ = tokio::time::timeout(Duration::from_secs(6), handle).await;
}

#[tokio::test]
async fn unwritable_path_does_not_panic_or_propagate() {
    // Pointing the sink at /dev/null/foo (not writable) — every append
    // should fail silently. The sink must remain usable (subsequent
    // calls are still no-ops).
    let cfg = JsonlSinkConfig {
        path: "/dev/null/audit.jsonl".into(),
        max_bytes: 1024,
        keep_files: 5,
    };
    // Construction may legitimately fail because the parent isn't a dir.
    // The sink-or-no-op contract: caller should be able to handle the
    // construction error gracefully. We don't expose Option<JsonlSink>
    // here — JsonlSink::new returns Result. Test: New returns Err, but
    // that's a startup-time signal to the daemon, not a runtime panic.
    let result = JsonlSink::new(cfg);
    assert!(
        result.is_err(),
        "unwritable path is rejected at construction"
    );
}
