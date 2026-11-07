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

#[test]
fn blocklist_serials_match_the_validator_form() {
    use agent_locksmith::mtls::blocklist::canonical_serial;
    for raw in ["7A:11", "0x7a11", "007a11", "7a11"] {
        assert_eq!(canonical_serial(raw).as_deref(), Some("7a11"), "{raw}");
    }
    assert_eq!(canonical_serial("a11").as_deref(), Some("0a11"));
    assert_eq!(canonical_serial("0").as_deref(), Some("00"));
    assert_eq!(canonical_serial("not-hex"), None);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocklist");
    std::fs::write(&path, "7A:11\nnot-hex\n").unwrap();
    let list = agent_locksmith::mtls::Blocklist::open(&path);
    assert!(list.contains("7a11"));
    assert_eq!(list.len(), 1, "non-hex line skipped");
}

#[cfg(unix)]
#[test]
fn atomic_write_replaces_contents_and_keeps_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocklist");
    std::fs::write(&path, "old\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    agent_locksmith::mtls::blocklist::write_atomic(&path, b"7a11\n").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "7a11\n");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640);
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "no temp left"
    );
}

#[cfg(unix)]
#[test]
fn atomic_write_refuses_a_symlinked_path() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("elsewhere");
    std::fs::write(&target, "keep\n").unwrap();
    let link = dir.path().join("blocklist");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    for write in [
        agent_locksmith::mtls::blocklist::write_atomic,
        agent_locksmith::mtls::blocklist::write_atomic_keeping_owner,
    ] {
        assert!(write(&link, b"7a11\n").is_err());
    }
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep\n");
}
