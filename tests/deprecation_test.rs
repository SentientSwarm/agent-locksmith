//! T1.5 — DeprecationRegistry behavior.
//!
//! Covers: R-F2, R-N5, INF-15, INF-24, Q-25.

use agent_locksmith::deprecation::{DeprecationDisposition, DeprecationEntry, DeprecationRegistry};

fn registry_with_test_entries() -> DeprecationRegistry {
    DeprecationRegistry::new(vec![
        DeprecationEntry {
            field_path: "tools[].cloud",
            disposition: DeprecationDisposition::Renamed {
                new_name: "tools[].egress",
            },
            since_version: "0.2.0",
            removal_target: Some("0.3.0"),
        },
        DeprecationEntry {
            field_path: "telemetry",
            disposition: DeprecationDisposition::Removed,
            since_version: "0.2.0",
            removal_target: None,
        },
    ])
}

#[test]
fn test_lookup_finds_known_entry() {
    let reg = registry_with_test_entries();
    let entry = reg.lookup("tools[].cloud");
    assert!(entry.is_some(), "expected `tools[].cloud` to be registered");
    assert!(matches!(
        entry.unwrap().disposition,
        DeprecationDisposition::Renamed { .. }
    ));
}

#[test]
fn test_lookup_returns_none_for_unknown_field() {
    let reg = registry_with_test_entries();
    assert!(reg.lookup("definitely_not_registered").is_none());
}

#[test]
fn test_renamed_field_warns_once_per_registry() {
    let reg = registry_with_test_entries();
    let first = reg.notice("tools[].cloud");
    let second = reg.notice("tools[].cloud");
    assert!(first, "first occurrence should be warned");
    assert!(
        !second,
        "subsequent occurrences must be silenced (one-shot per registry)"
    );
}

#[test]
fn test_unrelated_fields_warn_independently() {
    let reg = registry_with_test_entries();
    let cloud = reg.notice("tools[].cloud");
    let telemetry = reg.notice("telemetry");
    assert!(cloud);
    assert!(
        telemetry,
        "different deprecated fields each get their own one-shot warning"
    );
}

#[test]
fn test_notice_for_unknown_field_does_not_panic_and_returns_false() {
    let reg = registry_with_test_entries();
    assert!(!reg.notice("definitely_not_registered"));
}

#[test]
fn test_removed_field_disposition_is_ignored() {
    let reg = registry_with_test_entries();
    let entry = reg.lookup("telemetry").unwrap();
    assert!(matches!(entry.disposition, DeprecationDisposition::Removed));
}

#[test]
fn test_concurrent_notice_silences_after_first_winner() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    let reg = Arc::new(registry_with_test_entries());
    let true_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..16 {
        let reg = Arc::clone(&reg);
        let counter = Arc::clone(&true_count);
        handles.push(thread::spawn(move || {
            if reg.notice("tools[].cloud") {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        true_count.load(Ordering::SeqCst),
        1,
        "exactly one of N concurrent notice() calls should return true"
    );
}
