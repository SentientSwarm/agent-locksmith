//! T6.4 — local emergency blocklist.

use agent_locksmith::mtls::Blocklist;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn empty_blocklist_when_file_absent() {
    let dir = TempDir::new().unwrap();
    let bl = Blocklist::open(dir.path().join("absent"));
    assert!(bl.is_empty());
    assert!(!bl.contains("deadbeef"));
}

#[test]
fn parses_serials_skips_comments_and_blanks() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("blocklist");
    std::fs::write(
        &p,
        "# header\n\nDEADBEEF\n\n   # indented\nabc123\n# trailing\n",
    )
    .unwrap();
    let bl = Blocklist::open(&p);
    assert_eq!(bl.len(), 2);
    // Case-insensitive containment.
    assert!(bl.contains("deadbeef"));
    assert!(bl.contains("DEADBEEF"));
    assert!(bl.contains("abc123"));
    assert!(!bl.contains("00ff"));
}

#[test]
fn reload_picks_up_mtime_change() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("blocklist");
    std::fs::write(&p, "aaaa\n").unwrap();
    let bl = Blocklist::open(&p);
    assert!(bl.contains("aaaa"));
    assert!(!bl.contains("bbbb"));

    // Sleep enough for mtime granularity (FAT/HFS sometimes 1s).
    std::thread::sleep(Duration::from_secs(1));
    std::fs::write(&p, "bbbb\n").unwrap();
    assert!(bl.reload_if_changed(), "reload signaled new content");
    assert!(!bl.contains("aaaa"));
    assert!(bl.contains("bbbb"));

    // Idempotent: a second call with no change is a no-op.
    assert!(!bl.reload_if_changed());
}
