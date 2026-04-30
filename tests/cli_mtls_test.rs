//! T6.9 — locksmith mtls subcommands.
//!
//! revoke writes the serial; list-blocklist reads it. Both operate on
//! a local file path so we don't need a running daemon for the smoke
//! test.

use std::process::Command;
use tempfile::TempDir;

const LOCKSMITH: &str = env!("CARGO_BIN_EXE_locksmith");

#[test]
fn mtls_revoke_then_list_round_trip() {
    let dir = TempDir::new().unwrap();
    let blocklist = dir.path().join("blocklist");

    let out = Command::new(LOCKSMITH)
        .args(["mtls", "revoke", "DEADBEEF", "--blocklist-path"])
        .arg(&blocklist)
        .args(["--reason", "test revoke"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "revoke exits 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let raw = std::fs::read_to_string(&blocklist).unwrap();
    // Reason recorded as comment; serial normalized to lowercase.
    assert!(raw.contains("# test revoke"));
    assert!(raw.contains("deadbeef"));

    let out = Command::new(LOCKSMITH)
        .args([
            "--format",
            "json",
            "mtls",
            "list-blocklist",
            "--blocklist-path",
        ])
        .arg(&blocklist)
        .output()
        .unwrap();
    assert!(out.status.success());
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let serials: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(serials.contains(&"deadbeef"));
}
